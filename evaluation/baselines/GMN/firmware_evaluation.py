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
os.environ["CUDA_VISIBLE_DEVICES"] = "0"
use_cuda = torch.cuda.is_available()
device = torch.device('cuda:0' if use_cuda else 'cpu')

Graph = collections.namedtuple('Graph', [
    'graph', 'idb', 'func', 'fva'])

class BinSim:
    def __init__(self, vul_path, firmware_path, similarity_path):
        config = get_default_config()
        model, optimizer = build_model(config, 68, 4)
        model.to(device)
        self.model, self.optimizer, self.config = model, optimizer, config
        self.opcode_dict = read_json('gen_dataset/microcode_op_dict.json')
        self.opcode_dict = {d: c for c, d in enumerate(self.opcode_dict.keys())}
        self.vul_dataset = read_pickle(vul_path)
        self.firmware_dataset = read_pickle(firmware_path)
        
        self.similarity_path = similarity_path
        if os.path.exists(similarity_path):
            self.similarity_dict = read_json(similarity_path)
        else:
            self.similarity_dict = dict()
    
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
    
    def get_graph(self, g, idb, hex_fva, fn):
        return Graph(graph=g, idb=idb, fva=hex_fva, func=fn.strip('\"'))
    
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

    def evaluation(self, total):
        recall1_cnt = 0
        recall10_cnt = 0
        total_cnt = 0
        tgts = []
        res_csv = f'vul_firmware_res.csv'
        res = open(res_csv, 'w')
        content = 'proj,version,bin_name,func_name,fva,CVEs,rank,cand_bin,cand_name,cand_fva,similarity\n'
        res.write(content)
        for idb_path in self.firmware_dataset.keys():
            for hex_fva in self.firmware_dataset[idb_path].keys():
                firmware = self.firmware_dataset[idb_path][hex_fva]
                tgt = self.get_graph(firmware['graph'], idb_path, hex_fva, firmware['func_name'])
                tgts.append(tgt)
        
        for idb_path in self.vul_dataset.keys():
            tmp = idb_path.split('vuls_new/')[-1]
            items = tmp.split('/')
            proj, version, bin_name = items[0], items[1], items[2].split('.i64')[0]
            print(proj, version, bin_name)
            for hex_fva in self.vul_dataset[idb_path].keys():
                vul = self.vul_dataset[idb_path][hex_fva]
                src = self.get_graph(vul['graph'], idb_path, hex_fva, vul['func_name'])
                eval_graphs = []

                parts_num = 20
                waiting_list = []
                waiting_list_num = 0
                index = 0
                total_tgt = len(tgts)
                while index < total_tgt:
                    tgt = tgts[index]
                    index += 1
                    sim = self.query_similarity(src, tgt)
                    if sim is None:
                        if tgt.graph is not None:
                            waiting_list.append(tgt)
                            waiting_list_num += len(list(tgt.graph.nodes))
                    else:
                        eval_graphs.append({'idb':tgt.idb, 'func':tgt.func, 'fva': tgt.fva,
                                    'sim': sim})
                        
                    if len(waiting_list) == parts_num or index == total_tgt:
                        if len(waiting_list) == 0:
                            continue
                        tgt_pairs = [(src.graph, tgt.graph) for tgt in waiting_list]
                        sims = self.cal_similarity(tgt_pairs).tolist()
                        eval_graphs.extend([{'idb':tgt.idb, 'func':tgt.func, 'fva': tgt.fva,
                                        'sim': sim} for tgt, sim in zip(waiting_list, sims)])
                        waiting_list = []
                        waiting_list_num = 0
                
                self.write_similarity(src, eval_graphs)
                eval_graphs = sorted(eval_graphs, key=lambda x:x['sim'], reverse=True)
                
                rank = 0
                for graph in eval_graphs[:50]:
                    rank += 1
                    CVEs = vul['CVEs']
                    cand_bin = graph['idb'].split('.i64')[0]
                    cand_name = graph['func']
                    cand_fva = graph['fva']
                    similarity = graph['sim']
                    content = f'{proj},{version},{bin_name},{src.func},{src.fva},{CVEs},{rank},{cand_bin},{cand_name},{cand_fva},{similarity}\n'
                    print(content)
                    res.write(content)
                    
        res.close()
        write_json(self.similarity_dict, self.similarity_path)
            
if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(description='GMN')
    ap.add_argument('-v', '--vul_path', type=str)
    ap.add_argument('-f', '--firmware_path', type=str)
    ap.add_argument('-s', '--similarity_path', type=str)
    args = ap.parse_args()
    binsim = BinSim(args.vul_path, args.firmware_path, args.similarity_path)
    binsim.evaluation(1000)

# python3 firmware_evaluation.py -v gen_dataset/vul_dataset.pkl -f gen_dataset/firmware_dataset.pkl -s vul_firmware_res.json
