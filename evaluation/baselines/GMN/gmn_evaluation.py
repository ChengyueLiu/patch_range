import os
# os.environ["CUDA_DEVICE_ORDER"] = "PCI_BUS_ID"
# os.environ["CUDA_VISIBLE_DEVICES"] = "1"
import torch
from utils import *
from configure import *
from dataset import GraphEditDistanceDataset
from gen_dataset.tool_function import read_pickle, write_json, read_json
from evaluation import compute_similarity
import time
from tqdm import tqdm
import networkx as nx
import collections
import random
import pandas as pd

use_cuda = torch.cuda.is_available()
device = torch.device('cuda:0' if use_cuda else 'cpu')

class BinSim:
    def __init__(self, dataset_path, similarity_path, pos_path, neg_path):
        config = get_default_config()
        model, optimizer = build_model(config, 68, 4)
        model.to(device)
        self.model, self.optimizer, self.config = model, optimizer, config
        self.opcode_dict = read_json('gen_dataset/microcode_op_dict.json')
        self.opcode_dict = {d: c for c, d in enumerate(self.opcode_dict.keys())}
        self.dataset = read_pickle(dataset_path)
        self.similarity_path = similarity_path
        if os.path.exists(similarity_path):
            self.similarity_dict = read_json(similarity_path)
        else:
            self.similarity_dict = dict()
        self.pos_data = pd.read_csv(pos_path)
        self.pos_data.columns.values[0] = 'idx'
        self.neg_data = pd.read_csv(neg_path)
        self.neg_data.columns.values[0] = 'idx'
        
    def save_similarity(self, src, eval_graphs):
        src_key = src.idb + '/' + str(src.fva)
        if src_key not in self.similarity_dict.keys():
            self.similarity_dict[src_key] = dict()
        for graph in eval_graphs:
            tgt_key = graph['idb'] + '/' + str(graph['fva'])
            self.similarity_dict[src_key][tgt_key] = graph['sim']
        # write_json(self.similarity_dict, self.similarity_path)
        
    def graph_to_tensor(self, graph_pairs, size):
        batch = GraphEditDistanceDataset._pack_batch(graph_pairs)
        node_features, edge_features, from_idx, to_idx, graph_idx = get_graph(batch)
        graph_vectors = self.model(node_features.to(device), edge_features.to(device), from_idx.to(device), to_idx.to(device),
                            graph_idx.to(device), size * 2)
        x, y = reshape_and_split_tensor(graph_vectors, 2)
        return x, y
    
    def get_graph(self, idb, fva, fn):
        fva = int(fva)
        hex_fva = hex(fva)
        if idb in self.dataset.keys() and hex_fva in self.dataset[idb].keys():
            g = self.dataset[idb][hex_fva]
        else:
            return None
        Graph = collections.namedtuple('Graph', [
            'graph', 'idb', 'func', 'fva'])
        return Graph(graph=g, idb=idb, fva=fva, func=fn.strip('\"'))
    
    def gen_validation(self, idx):
        print(idx)
        pos_df = self.pos_data[self.pos_data['idx'] == idx+1]
        poss = []
        for _, pos_row in pos_df.iterrows():
            # print(_)
            src_idb, src_fva, src_fn, src_idx = pos_row['idb_path_1'], pos_row['fva_1'], pos_row['func_name_1'], pos_row['idx_1']
            pos_idb, pos_fva, pos_fn = pos_row['idb_path_2'], pos_row['fva_2'], pos_row['func_name_2']
            pos = self.get_graph(pos_idb, pos_fva, pos_fn)
            if pos is not None:
                poss.append(pos)
    
        src = self.get_graph(src_idb, src_fva, src_fn)
        if src is None or len(poss) == 0:
            return None, None, None
        
        neg_df = self.neg_data[self.neg_data['idx_1'] == src_idx]
        negs = []
        for _, neg_row in neg_df.iterrows():
            neg_idb, neg_fva, neg_fn = neg_row['idb_path_2'], neg_row['fva_2'], neg_row['func_name_2']
            neg = self.get_graph(neg_idb, neg_fva, neg_fn)
            if neg is not None:
                negs.append(neg)

        return src, poss, negs
    
    def cos_similarity(self, graph_pairs):
        x, y = self.graph_to_tensor(graph_pairs, len(graph_pairs))
        similarity = compute_similarity(self.config, x, y)
        return similarity
        
    def query_similarity(self, src, tgt):
        src_key = src.idb + '/' + str(src.fva)
        tgt_key = tgt.idb + '/' + str(tgt.fva)
        if src_key in self.similarity_dict.keys() and tgt_key in self.similarity_dict[src_key].keys():
            sim = self.similarity_dict[src_key][tgt_key]
            return sim
        if tgt_key in self.similarity_dict.keys() and src_key in self.similarity_dict[tgt_key].keys():
            sim = self.similarity_dict[tgt_key][src_key]
            return sim
        return None

    def gmn_similarity(self, src, tgts, gt):
        eval_graphs = []
        waiting_list = []
        waiting_nodes = 0
        for idx, tgt in enumerate(tgts):
            tgt_sim = self.query_similarity(src, tgt)
            if tgt_sim is None:
                waiting_nodes += max(len(list(src.graph.nodes)), len(list(tgt.graph.nodes)))
                waiting_list.append(tgt)
            else:
                eval_graphs.append({'idb': tgt.idb, 'func': tgt.func, 'fva':tgt.fva, 'sim': tgt_sim, 'gt': gt})
            
            if waiting_nodes > 10000 or idx == len(tgts) - 1:
                if len(waiting_list) > 0:
                    tgt_pairs = [(src.graph, tgt.graph) for tgt in waiting_list]
                    tgt_sims = self.cos_similarity(tgt_pairs).tolist()
                    eval_graphs.extend([{'idb':tgt.idb, 'func':tgt.func, 'fva': tgt.fva,
                                        'sim': tgt_sim, 'gt': gt} for tgt, tgt_sim in zip(waiting_list, tgt_sims)])
                    waiting_list = []
                    waiting_nodes = 0
        return eval_graphs
                    
    def evaluation(self, total):
        # recall1_cnt = 0
        # recall10_cnt = 0
        for idx in tqdm(range(total), desc=f'Eval for GMN'):
            src, poss, negs = self.gen_validation(idx)
            if src is None or len(poss) == 0 or len(negs) == 0:
                continue
            
            eval_graphs = []
            pos_evals = self.gmn_similarity(src, poss, 1)
            neg_evals = self.gmn_similarity(src, negs, -1)
            eval_graphs = pos_evals + neg_evals
            self.save_similarity(src, eval_graphs)
            # eval_graphs = sorted(eval_graphs, key=lambda x:x['sim'], reverse=True)
            # index = 0
            # for graph in eval_graphs:
            #     index += 1
            #     if index == 1:
            #         print(f'top similarity: {graph["sim"]} {graph["idb"]} {graph["func"]}')
            #     if graph['gt'] == 1:
            #         print(f'pos similarity: {graph["sim"]} {graph["idb"]} {graph["func"]}')
            #         print(f'Index: {index}')
            #         break
            
            # if index <= 1:
            #     recall1_cnt += 1
            #     # print(f'recall1: {recall1_cnt}')
            # if index <= 10:
            #     recall10_cnt += 1
            #     # print(f'recall10: {recall10_cnt}')
        
        # recall1 = 1.0 * recall1_cnt / total
        # recall10 = 1.0 * recall10_cnt / total
        # print(f'recall1: {recall1:.4f} recall10: {recall10:.4f}')
        write_json(self.similarity_dict, self.similarity_path)
            
if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(description='GMN')
    ap.add_argument('-d', '--dataset', type=str, help='path to dataset')
    ap.add_argument('-s', '--similarity', type=str)
    ap.add_argument('-p', '--pos', type=str)
    ap.add_argument('-n', '--neg', type=str)
    args = ap.parse_args()
    binsim = BinSim(args.dataset, args.similarity, args.pos, args.neg)
    binsim.evaluation(1000)

# python3 gmn_evaluation.py -d gen_dataset/microcode_inline_test.pkl -s pools/inline/inline_test_realworld.json -p pools/inline/pos-realworld_test.csv -n pools/inline/neg-realworld_test.csv
