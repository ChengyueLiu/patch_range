import idautils
import idc
import idaapi
import ida_funcs
import ida_bytes
import ida_kernwin
import ida_hexrays
import networkx as nx
import re
import os
import random
import tqdm
import gc
from collections import Counter

def parse_instruction(ea, symbol_map, string_map):
    """
    解析指令，将操作数中的地址替换为相应的符号或字符串标记。
    """
    mnem = idc.print_insn_mnem(ea)  # 获取指令助记符
    if not mnem:
        return ""
    
    operands = []
    for i in range(6):  # 最多 6 个操作数
        op = idc.print_operand(ea, i)
        if not op:
            break
        symbols = re.split(r'([0-9A-Za-z]+)', op)
        for j in range(len(symbols)):
            if symbols[j].startswith("0x") and len(symbols[j]) >= 6:
                addr = int(symbols[j], 16)
                if addr in symbol_map:
                    symbols[j] = "symbol"
                elif addr in string_map:
                    symbols[j] = "string"
                else:
                    symbols[j] = "address"
        operands.append(" ".join(symbols))

    return " ".join([mnem] + operands)

def random_walk(g, length, symbol_map, string_map):
    """
    在 CFG 上进行随机游走，生成指令序列。
    """
    sequence = []
    for n in g:
        if n != -1 and g.nodes[n].get('text'):
            s = []
            l = 0
            s.append(parse_instruction(n, symbol_map, string_map))
            cur = n
            while l < length:
                nbs = list(g.successors(cur))
                if len(nbs):
                    cur = random.choice(nbs)
                    s.append(parse_instruction(cur, symbol_map, string_map))
                    l += 1
                else:
                    break
            sequence.append(s)
            if len(sequence) > 10:
                break
    return sequence

def process_file(out_file):
    """
    处理当前 IDA 加载的二进制文件，提取 CFG 进行随机游走。
    """
    symbol_map = {}
    string_map = {}

    # 解析符号信息
    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        symbol_map[func_ea] = func_name
    
    # 解析字符串常量
    for s in idautils.Strings():
        string_map[s.ea] = str(s)

    function_graphs = {}

    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        G = nx.DiGraph()
        G.add_node(-1, text='entry_point')
        label_dict = {-1: 'entry_point'}

        fc = idaapi.FlowChart(func)
        for block in fc:
            for head in idautils.Heads(block.start_ea, block.end_ea):
                disasm = idc.generate_disasm_line(head, 0)
                G.add_node(head, text=disasm)
                label_dict[head] = disasm

                # 变量依赖分析（如果 Hex-Rays 可用）
                if ida_hexrays.init_hexrays_plugin():
                    try:
                        cfunc = ida_hexrays.decompile(func_ea)
                        if cfunc:
                            for i in range(cfunc.treeitems.size()):
                                item = cfunc.treeitems[i]
                                if item.opname == "var_read" or item.opname == "var_write":
                                    G.add_edge(head, item.ea)
                    except Exception:
                        pass

                # 添加 CFG 边
                for succ in idautils.CodeRefsFrom(head, 1):  # 1 = flow control
                    if succ != head:
                        G.add_edge(head, succ)

        # 连接无前驱的块到 entry_point
        for node in G.nodes:
            if not G.in_degree(node):
                G.add_edge(-1, node)
        
        if len(G.nodes) > 2:
            function_graphs[idc.get_func_name(func_ea)] = G

    with open(out_file, "w") as w:
        for name, graph in function_graphs.items():
            sequence = random_walk(graph, 40, symbol_map, string_map)
            for s in sequence:
                if len(s) >= 2:
                    for idx in range(1, len(s)):
                        w.write(s[idx-1] + '\t' + s[idx] + '\n')
    
    gc.collect()

def process_string():
    """
    提取当前二进制文件中的字符串信息。
    """
    str_lst = []
    for s in idautils.Strings():
        str_lst.extend(re.findall(r'([0-9A-Za-z]+)', str(s)))
    return str_lst


if __name__ == '__main__':
    if not idaapi.get_plugin_options("idb"):
        print("[!] -Oidb option is missing")
        idc.qexit(1)

    idb_path = idaapi.get_plugin_options("idb")
    if not idb_path.endswith('.i64') and not idb_path.endswith('.idb'):
        print("[!] Invalid IDB path: %s" % idb_path)
        idc.qexit(1)

    process_file(idb_path.replace('.i64', '_palmtree_dfg.txt'))
    idc.qexit(0)