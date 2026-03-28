import idc
import idautils
import idaapi
import pickle
import binaryai
import networkx as nx
import pandas as pd

class BinaryData:
    def __init__(self):
        None

    def get_asm(self, func):
        instGenerator = idautils.FuncItems(func)
        asm_list = []
        for inst in instGenerator:
            asm_list.append(idc.GetDisasm(inst))
        return asm_list

    def get_rawbytes(self, func):
        instGenerator = idautils.FuncItems(func)
        rawbytes_list = b""
        for inst in instGenerator:
            rawbytes_list += idc.get_bytes(inst, idc.get_item_size(inst))
        return rawbytes_list

    def get_cfg(self, func):

        def get_attr(block, func_addr_set):
            asm,raw=[],b""
            curr_addr = block.start_ea
            if curr_addr not in func_addr_set:
                return -1
            # print(f"[*] cur: {hex(curr_addr)}, block_end: {hex(block.end_ea)}")
            while curr_addr <= block.end_ea:
                asm.append(idc.GetDisasm(curr_addr))
                raw+=idc.get_bytes(curr_addr, idc.get_item_size(curr_addr))
                curr_addr = idc.next_head(curr_addr, block.end_ea)
            return asm, raw

        nx_graph = nx.DiGraph()
        flowchart = idaapi.FlowChart(idaapi.get_func(func), flags=idaapi.FC_PREDS)
        func_addr_set = set([addr for addr in idautils.FuncItems(func)])
        for block in flowchart:
            # Make sure all nodes are added (including edge-less nodes)
            attr = get_attr(block, func_addr_set)
            if attr == -1:
                continue
            nx_graph.add_node(block.start_ea, asm=attr[0], raw=attr[1])
            # print(f"[*] bb: {hex(block.start_ea)}, asm: {attr[0]}")
            for pred in block.preds():
                if pred.start_ea not in func_addr_set:
                    continue
                nx_graph.add_edge(pred.start_ea, block.start_ea)
            for succ in block.succs():
                if succ.start_ea not in func_addr_set:
                    continue
                nx_graph.add_edge(block.start_ea, succ.start_ea)
        return nx_graph  

    def get_binai_feature(self, func):
        return binaryai.ida.get_func_feature(func)

    def extract_all(self):
        for func in idautils.Functions():
            if idc.get_segm_name(func) in ['.plt','extern','.init','.fini']:
                continue
            print("[+] %s" % idc.get_func_name(func))
            asm_list = self.get_asm(func)
            rawbytes_list = self.get_rawbytes(func)
            cfg = self.get_cfg(func)
            bai_feature = self.get_binai_feature(func)
            yield (func, asm_list, rawbytes_list, cfg, bai_feature)

if __name__ == "__main__":
    import os
    from collections import defaultdict

    if not idaapi.get_plugin_options("idb"):
        print("[!] -Oidb option is missing")
        idc.qexit(1)

    idb_path = idaapi.get_plugin_options("idb")

    idc.auto_wait()
    binary_data = BinaryData()

    saved_dict = defaultdict(lambda: list)
    if not idb_path.endswith('i64'):
        assert(0)
    saved_path = idb_path.replace('.i64', "_jtrans_fea.pkl")

    with open(saved_path, 'wb') as f:
        for func_ea, asm_list, rawbytes_list, cfg, bai_feature in binary_data.extract_all():
            saved_dict[func_ea] = [func_ea, asm_list, rawbytes_list, cfg, bai_feature]
        pickle.dump(dict(saved_dict), f)
        print('dump to', saved_path)
    idc.qexit(0)

