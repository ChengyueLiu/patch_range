import idautils
import idc
import idaapi
import networkx as nx
import random
import os
import re
from collections import Counter

def parse_instruction(ins, symbol_map, string_map):
    ins = re.sub('\s+', ', ', ins, 1)
    parts = ins.split(', ')
    operand = []
    if len(parts) > 1:
        operand = parts[1:]
    for i in range(len(operand)):
        symbols = re.split('([0-9A-Za-z]+)', operand[i])
        for j in range(len(symbols)):
            if symbols[j][:2] == '0x' and len(symbols[j]) >= 6:
                if int(symbols[j], 16) in symbol_map:
                    symbols[j] = "symbol"
                elif int(symbols[j], 16) in string_map:
                    symbols[j] = "string"
                else:
                    symbols[j] = "address"
        operand[i] = ' '.join(symbols)
    opcode = parts[0]
    return ' '.join([opcode]+operand)

def random_walk(g, length, symbol_map, string_map):
    sequence = []
    for n in g:
        if 'text' in g.nodes[n]:
            s = []
            l = 0
            s.append(parse_instruction(g.nodes[n]['text'], symbol_map, string_map))
            cur = n
            while l < length:
                nbs = list(g.successors(cur))
                if len(nbs):
                    cur = random.choice(nbs)
                    if 'text' in g.nodes[cur]:
                        s.append(parse_instruction(g.nodes[cur]['text'], symbol_map, string_map))
                        l += 1
                    else:
                        break
                else:
                    break
            sequence.append(s)
        if len(sequence) > 10:
            print("early stop")
            return sequence[:10]
    return sequence

def process_file(window_size, out_path):
    symbol_map = {}
    string_map = {}
    
    for ea in idautils.Functions():
        func_name = idc.get_func_name(ea)
        symbol_map[ea] = func_name
    
    for string in idautils.Strings():
        string_map[string.ea] = str(string)
    
    function_graphs = {}
    
    for func_ea in idautils.Functions():
        func = idaapi.get_func(func_ea)
        if not func:
            continue
        
        G = nx.DiGraph()
        label_dict = {}
        
        for block in idaapi.FlowChart(func):
            curr = block.start_ea
            predecessor = curr
            while curr < block.end_ea:
                disasm = idc.GetDisasm(curr)
                label_dict[curr] = disasm
                G.add_node(curr, text=disasm)
                if curr != block.start_ea:
                    G.add_edge(predecessor, curr)
                predecessor = curr
                curr = idc.next_head(curr, block.end_ea)
            for succ_block in block.succs():
                G.add_edge(predecessor, succ_block.start_ea)
        
        if len(G.nodes) > 2:
            function_graphs[idc.get_func_name(func_ea)] = G
    
    with open(out_path, 'w') as w:
        for name, graph in function_graphs.items():
            sequence = random_walk(graph, 40, symbol_map, string_map)
            for s in sequence:
                if len(s) >= 4:
                    for idx in range(len(s)):
                        for i in range(1, window_size + 1):
                            if idx - i > 0:
                                w.write(s[idx - i] + '\t' + s[idx] + '\n')
                            if idx + i < len(s):
                                w.write(s[idx] + '\t' + s[idx + i] + '\n')


if __name__ == '__main__':
    window_size = 1
    if not idaapi.get_plugin_options("idb"):
        print("[!] -Oidb option is missing")
        idc.qexit(1)

    idb_path = idaapi.get_plugin_options("idb")
    if not idb_path.endswith('.i64') and not idb_path.endswith('.idb'):
        print("[!] Invalid IDB path: %s" % idb_path)
        idc.qexit(1)

    process_file(window_size, idb_path.replace('.i64', '_palmtree_cfg.txt'))
    idc.qexit(0)