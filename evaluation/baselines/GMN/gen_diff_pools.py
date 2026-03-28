import os
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

os.environ["CUDA_DEVICE_ORDER"] = "PCI_BUS_ID"
# os.environ["CUDA_VISIBLE_DEVICES"] = "1"
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
        self.pos = open(pos_path, 'r')
        self.neg = open(neg_path, 'r')
        self.token = pos_path.split('/')[-1].split('.')[0].split('-')[-1]
        self.bad_case_path = f'result/{self.token}_inline-gmn_bad_case.txt'
    
    def write_similarity(self, src, eval_graphs):
        src_key = src.idb + '/' + str(src.fva)
        if src_key not in self.similarity_dict.keys():
            self.similarity_dict[src_key] = dict()
        for graph in eval_graphs:
            tgt_key = graph['idb'] + '/' + str(graph['fva'])
            self.similarity_dict[src_key][tgt_key] = graph['sim']
        
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
        # g = None
        Graph = collections.namedtuple('Graph', [
            'graph', 'idb', 'func', 'fva'])
        return Graph(graph=g, idb=idb, fva=fva, func=fn.strip('\"'))
    
    def gen_validation(self):
        line = self.pos.readline()
        items = line.split(',')
        src_idb, src_fva, src_fn, pos_idb, pos_fva, pos_fn = items[1], items[2], items[3], items[5], items[6], items[7]
        src = self.get_graph(src_idb, src_fva, src_fn)
        pos = self.get_graph(pos_idb, pos_fva, pos_fn)

        negs = []
        for i in range(10000):
            line = self.neg.readline()
            items = line.split(',')
            neg_idb, neg_fva, neg_fn =items[5], items[6], items[7]
            neg = self.get_graph(neg_idb, neg_fva, neg_fn)
            if neg is not None:
                negs.append(neg)
        if src is None or pos is None:
            return None, None, None
        return src, pos, negs
    
    def cal_similarity(self, graph_pairs):
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

    def save_bad_case(self, src, pos, neg1, neg2):
        if neg1 is None or neg2 is None:
            return
        pos_rank = pos[1]
        pos = pos[0]
        neg_rank1 = neg1[1]
        neg1 = neg1[0]
        neg_rank2 = neg2[1]
        neg2 = neg2[0]
        
        if not os.path.exists(self.bad_case_path):
            with open(self.bad_case_path, 'w') as f:
                s = 'idb, faddr\n' + \
                    'pos_name, pos_idb, pos_addr, pos_sim, pos_rank\n' + \
                    'neg_name1, neg_idb1, neg_addr1, neg_sim1, neg_rank1\n' + \
                    'neg_name2, neg_idb2, neg_addr2, neg_sim2, neg_rank2\n\n'
                f.write(s)
        
        with open(self.bad_case_path, 'a+') as f:
            s = f'————————————————————————————————————————————————————————————————————————————————————————\n' + \
                f'{src.idb}, {src.fva}\n' + \
                f'{pos["func"]}, {pos["idb"]}, {pos["fva"]}, {pos["sim"]}, {pos_rank}\n' + \
                f'{neg1["func"]}, {neg1["idb"]}, {neg1["fva"]}, {neg1["sim"]}, {neg_rank1}\n' + \
                f'{neg2["func"]}, {neg2["idb"]}, {neg2["fva"]}, {neg2["sim"]}, {neg_rank2}\n\n'
            f.write(s)

    def evaluation(self, total):
        total_cnt = 0
        pool_sizes = [2,4,8,16,32,64,100,128,256,512,1024,2048,5000,8000,8192,9000,10000]
        res_dict = dict()
        for pool_size in pool_sizes:
            if pool_size not in res_dict.keys():
                res_dict[pool_size] = {
                    'recall1':0,
                    'recall5':0,
                    'recall10':0,
                    'recall20':0,
                    'recall30':0,
                    'recall40':0,
                    'recall50':0,
                    'recall100':0,
                    'mrr':0,
                }
        _ = self.pos.readline()
        _ = self.neg.readline()
        for r in tqdm(range(total), desc=f'Eval for GMN'):
            src, pos, negs = self.gen_validation()
            if src is None or pos is None or len(negs) == 0:
                continue
            total_cnt += 1
            eval_graphs = []
            
            # pos
            pos_sim = self.query_similarity(src, pos)
            if pos_sim is None:
                print(f'pos not in dict.')
                pos_pair = [(src.graph, pos.graph)]
                pos_sim = self.cal_similarity(pos_pair).item()
            eval_graphs.append({'idb':pos.idb, 'func':pos.func, 'fva': pos.fva,
                                'sim': pos_sim, 'gt': 1})
            # neg
            parts_num = 20
            waiting_list = []
            index = 0
            total_neg = len(negs)
            
            while index < total_neg:
                neg = negs[index]
                index += 1
                neg_sim = self.query_similarity(src, neg)
                if neg_sim is None:
                    print(f'neg not in dict.')
                    waiting_list.append(neg)
                else:
                    eval_graphs.append({'idb':neg.idb, 'func':neg.func, 'fva': neg.fva,
                                'sim': neg_sim, 'gt': -1})
                    
                if len(waiting_list) == parts_num or index == total_neg:
                    if len(waiting_list) == 0:
                        continue
                    neg_pairs = [(src.graph, neg.graph) for neg in waiting_list]
                    neg_sims = self.cal_similarity(neg_pairs).tolist()
                    eval_graphs.extend([{'idb':neg.idb, 'func':neg.func, 'fva': neg.fva,
                                     'sim': neg_sim, 'gt': -1} for neg, neg_sim in zip(waiting_list, neg_sims)])
                    waiting_list = []
            
            self.write_similarity(src, eval_graphs)

            for pool_size in pool_sizes:
                eval_pool = sorted(eval_graphs[:pool_size], key=lambda x:x['sim'], reverse=True)
                index = 0
                neg_graph1, neg_graph2 = None, None
                for graph in eval_pool:
                    index += 1
                    if graph['gt'] == 1:
                        pos_graph = (graph, index)
                        break
                    if index == 1:
                        neg_graph1 = (graph, index)
                    if index == 2:
                        neg_graph2 = (graph, index)
                
                if index <= 1:
                    res_dict[pool_size]['recall1'] += 1
                if index <= 5:
                    res_dict[pool_size]['recall5'] += 1
                if index <= 10:
                    res_dict[pool_size]['recall10'] += 1
                else:
                    if pool_size == 10000 and neg_graph1 is not None and neg_graph2 is not None:
                        self.save_bad_case(src, pos_graph, neg_graph1, neg_graph2)
                if index <= 20:
                    res_dict[pool_size]['recall20'] += 1
                if index <= 30:
                    res_dict[pool_size]['recall30'] += 1
                if index <= 40:
                    res_dict[pool_size]['recall40'] += 1
                if index <= 50:
                    res_dict[pool_size]['recall50'] += 1
                if index <= 100:
                    res_dict[pool_size]['recall100'] += 1

                res_dict[pool_size]['mrr'] += 1.0/index
        
        for pool_size in res_dict.keys():
            for rate in res_dict[pool_size].keys():
                res_dict[pool_size][rate] = res_dict[pool_size][rate] * 1.0 / total_cnt
        
        print(res_dict)
        write_json(self.similarity_dict, self.similarity_path)
        return res_dict
    
def save_result(res, res_path):
    with open(res_path, 'w') as f:
        s = 'pool,Recall_1,Recall_5,Recall10,Recall_20,Recall_30,Recall_40,Recall_50,Recall_100,MRR\n'
        for pool_size in res.keys():
            s += f'{pool_size},{res[pool_size]["recall1"]},{res[pool_size]["recall5"]},' + \
                 f'{res[pool_size]["recall10"]},{res[pool_size]["recall20"]},{res[pool_size]["recall30"]},' + \
                 f'{res[pool_size]["recall40"]},{res[pool_size]["recall50"]},{res[pool_size]["recall100"]},{res[pool_size]["mrr"]}\n'
        f.write(s)
        
if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(description='GMN')
    ap.add_argument('-d', '--dataset', type=str, help='path to dataset')
    ap.add_argument('-s', '--similarity', type=str)
    ap.add_argument('-p', '--pos', type=str)
    ap.add_argument('-n', '--neg', type=str)
    ap.add_argument('-r', '--result', type=str)
    args = ap.parse_args()
    binsim = BinSim(args.dataset, args.similarity, args.pos, args.neg)
    res = binsim.evaluation(1000)
    save_result(res, args.result)
    

#  python3 gen_diff_pools.py -d gen_dataset/microcode_inline_test.pkl -s pools/inline/inline_test_realworld.json -p pools/inline/pos-realworld_test.csv -n pools/inline/neg-realworld_test.csv -r result/inline_test_xo86_inline-gmn_result.csv 