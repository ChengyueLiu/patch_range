import os
import torch
from utils import *
from configure import *
from dataset import GraphEditDistanceDataset
from gen_dataset.tool_function import read_pickle, write_json
from evaluation import compute_similarity
import time
from tqdm import tqdm
import networkx as nx
import collections

os.environ["CUDA_DEVICE_ORDER"] = "PCI_BUS_ID"
os.environ["CUDA_VISIBLE_DEVICES"] = "1"
use_cuda = torch.cuda.is_available()
device = torch.device('cuda:0' if use_cuda else 'cpu')

class BinSim:
    def __init__(self, dataset_path):
        config = get_default_config()
        model, optimizer = build_model(config, 68, 4)
        model.to(device)
        self.model, self.optimizer, self.config = model, optimizer, config
        self.dataset = read_pickle(dataset_path)
        
    def graph_to_tensor(self, graph_pairs, size):
        batch = GraphEditDistanceDataset._pack_batch(graph_pairs)
        node_features, edge_features, from_idx, to_idx, graph_idx = get_graph(batch)
        graph_vectors = self.model(node_features.to(device), edge_features.to(device), from_idx.to(device), to_idx.to(device),
                            graph_idx.to(device), size * 2)
        x, y = reshape_and_split_tensor(graph_vectors, 2)
        return x, y
    
    def get_graph(self, binary=None, func_name=None, index=None):
        b = random.choice(list(self.dataset.keys())) if binary == None else binary
        f = random.choice(list(self.dataset[b].keys())) if func_name == None else func_name
        i = random.randint(0, len(self.dataset[b][f])-1) if index == None else index
        # return self.dataset[b][f][i], b, f, i
        Graph = collections.namedtuple('Graph', [
            'graph', 'binary', 'func', 'index'])
        return Graph(graph=self.dataset[b][f][i], binary=b, func=f, index=i)
            
    def gen_validation(self):
        binary, func, index = None, None, None
        # gen src
        while True:
            src = self.get_graph()
            if len(self.dataset[src.binary][src.func]) > 1:
                binary, func, index = src.binary, src.func, src.index
                break
            
        # gen pos
        while True:
            pos = self.get_graph(binary, func)
            if pos.index != index:
                break
        
        # gen neg
        negs = []
        while len(negs) < 10000:
            neg = self.get_graph()
            if neg.func == func:
                continue
            negs.append(neg)
        
        return src, pos, negs
    
    def get_similarity(self, graph_pairs):
        x, y = self.graph_to_tensor(graph_pairs, len(graph_pairs))
        similarity = compute_similarity(self.config, x, y)
        return similarity

    def test(self, total=1):
        g, b, f, i = self.get_graph()
        g2 = g.copy()
        # num = g.number_of_nodes()
        num = g.number_of_edges()
        for i in range(num-2):
            n = random.choice(list(g2.nodes))
            g2.remove_node(n)
            # s, e = random.choice(list(g2.edges))
            # g2.remove_edge(s, e)
            mapping = {node: idx for idx, node in enumerate(g2.nodes, start=0)}
            g2 = nx.relabel_nodes(g2, mapping, copy=False)
            g_pair = [(g, g2)]
            sim = self.get_similarity(g_pair).item()
            print(sim)
        # s, e = random.choice(list(g2.edges))
        # g2.remove_edge(s, e)
        
    def evaluation(self, total):
        recall1_cnt = 0
        recall10_cnt = 0
        for r in tqdm(range(total), desc=f'Eval for GMN'):
            src, pos, negs = self.gen_validation()
            eval_graphs = []
            
            # pos
            pos_pair = [(src.graph, pos.graph)]
            pos_sim = self.get_similarity(pos_pair).item()
            eval_graphs.append({'graph': pos.graph, 'binary':pos.binary, 'func':pos.func, 'index':pos.index,
                                'sim': pos_sim, 'gt': 1})
            
            # neg
            parts_num = 100
            parts = int((len(negs)-1) / parts_num + 1)
            for part in range(parts):
                part_negs = negs[part*parts_num:(part+1)*parts_num]
                neg_pairs = [(src.graph, neg.graph) for neg in part_negs]
                neg_sims = self.get_similarity(neg_pairs).tolist()
                eval_graphs.extend([{'graph': neg.graph, 'binary':neg.binary, 'func':neg.func, 'index':neg.index,
                                     'sim': neg_sim, 'gt': -1} for neg, neg_sim in zip(part_negs, neg_sims)])
            
            eval_graphs = sorted(eval_graphs, key=lambda x:x['sim'], reverse=True)
            index = 0
            for graph in eval_graphs:
                index += 1
                if index == 1:
                    print(f'top similarity: {graph["sim"]} {graph["binary"]} {graph["func"]} {graph["index"]}')
                if graph['gt'] == 1:
                    print(f'pos similarity: {graph["sim"]} {graph["binary"]} {graph["func"]} {graph["index"]}')
                    print(f'Index: {index}')
                    break
            
            if index <= 1:
                recall1_cnt += 1
                print(f'recall1: {recall1_cnt}')
            if index <= 10:
                recall10_cnt += 1
                print(f'recall10: {recall10_cnt}')
        
        recall1 = 1.0 * recall1_cnt / total
        recall10 = 1.0 * recall10_cnt / total
        print(f'recall1: {recall1:.4f} recall10: {recall10:.4f}')
            
if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(description='GMN')
    ap.add_argument('-d', '--dataset', type=str, help='path to dataset')
    ap.add_argument('-n', '--num', type=int)
    args = ap.parse_args()
    binsim = BinSim(args.dataset)
    # binsim.test()
    binsim.evaluation(args.num)