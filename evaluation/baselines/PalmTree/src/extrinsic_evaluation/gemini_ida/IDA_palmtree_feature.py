import glob
import pickle
import time
import re
import os
# os.environ['CUDA_VISIBLE_DEVICES'] = '3,4'
import numpy as np
import eval_utils as utils

import idautils
import idaapi
import idc
from idautils import Functions, Strings, CodeRefsFrom
from idaapi import get_func, get_func_name, FlowChart
from idc import GetDisasm

from obj import Obj


class BasicBlockMap(dict):
    def __missing__(self, key):
        v = len(self)
        self[key] = v
        return v

def encode_str(string):
    vector = [0] * 256
    for u in string:
        vector[ord(u)] += 1
    return ''.join(map(str, vector))

def parse_instruction(ins, symbol_map, string_map):
    ins = re.sub('\s+', ', ', ins, 1)
    parts = ins.split(', ')
    token_lst = [parts[0]]
    if len(parts) > 1:
        operands = parts[1:]
        for op in operands:
            symbols = re.split('([0-9A-Za-z]+)', op)
            symbols = [s.strip() for s in symbols if s]
            for j in range(len(symbols)):
                if symbols[j].startswith('0x') and len(symbols[j]) == 10:
                    addr = int(symbols[j], 16)
                    if addr in symbol_map:
                        symbols[j] = "symbol"
                    elif addr in string_map:
                        symbols[j] = "string"
                    else:
                        symbols[j] = "address"
            token_lst.extend(symbols)
    return ' '.join(token_lst)

def calc_st_embeddings(usable_encoder, block, symbol_map, string_map):
    text = []
    for head in range(block.start_ea, block.end_ea):
        insn = GetDisasm(head)
        text.append(parse_instruction(insn, symbol_map, string_map))
    if text:
        if len(text) > 50:
            text = text[:50]
        embd = np.sum(usable_encoder.encode(text), axis=0) / len(text)
    else:
        embd = np.zeros(128)
    return embd, text

def build_neighbors(func, bb_map):
    edge_list = []
    for block in FlowChart(func):
        src_id = bb_map[block.start_ea]
        for succ in block.succs():
            dst_id = bb_map[succ.start_ea]
            edge_list.append((src_id, dst_id))
    return edge_list

def disassemble(function_filter):
    symbol_map = {}
    string_map = {}
    
    for ea in idautils.Functions():
        func_name = idc.get_func_name(ea)
        symbol_map[ea] = func_name
    
    for string in idautils.Strings():
        string_map[string.ea] = str(string)
    usable_encoder = utils.UsableTransformer(model_path="/code/PalmTree/src/cdfg_bert_1/transformer.ep0", vocab_path="/code/PalmTree/src/cdfg_bert_1/vocab")
    s = time.time()

    raw_graph_list = []
    filter_count = 0
    
    for func_ea in Functions():
        func = get_func(func_ea)
        if not func:
            continue
        
        bb_map = BasicBlockMap()
        blocks = list(FlowChart(func))
        if len(blocks) < 5:
            continue
        
        edge_list = build_neighbors(func, bb_map)
        fvec_list = [0] * len(bb_map)
        ins_list = []
        
        for block in blocks:
            fv_list, ins = calc_st_embeddings(usable_encoder, block, symbol_map, string_map)
            fvec_list[bb_map[block.start_ea]] = fv_list
            ins_list.extend(ins)
        
        ins_text = ';'.join(ins_list)
        if ins_text not in function_filter:
            function_filter.append(ins_text)
            acfg = Obj()
            acfg.fv_list = fvec_list
            acfg.funcname = idaapi.get_func_name(func.start_ea)
            acfg.edge_list = edge_list
            raw_graph_list.append(acfg)
        else:
            filter_count += 1
    
    acfgs = Obj()
    acfgs.raw_graph_list = raw_graph_list
    elapse = time.time() - s
    print('-------', elapse)
    print("filter out functions: ", filter_count)
    return acfgs

if __name__ == '__main__':
    if not idaapi.get_plugin_options("idb"):
        print("[!] -Oidb option is missing")
        idc.qexit(1)

    idb_path = idaapi.get_plugin_options("idb")
    if not idb_path.endswith('.i64') and not idb_path.endswith('.idb'):
        print("[!] Invalid IDB path: %s" % idb_path)
        idc.qexit(1)

    function_filter = []
    acfgs = disassemble(function_filter)
    pickle.dump(acfgs, open(idb_path.replace('.i64', '_palmtree_fea.pkl'), 'wb'))

    idc.qexit(0)
