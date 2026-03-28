import json
import tree_sitter
import tree_sitter_cpp
from tqdm import tqdm
import os
os.environ["CUDA_VISIBLE_DEVICES"] = "0,1"
import argparse
from transformers import AutoTokenizer, AutoModel
import torch
import numpy as np
from tqdm import tqdm
import pickle
import json
import torch.nn.functional as F
def mean_pooling(model_output, attention_mask):
    token_embeddings = model_output[0]
    input_mask_expanded = attention_mask.unsqueeze(-1).expand(token_embeddings.size()).float()
    return torch.sum(token_embeddings * input_mask_expanded, 1) / torch.clamp(input_mask_expanded.sum(1), min=1e-9)


def is_variable_declaration(node):
    has_parameters = any(child.type == "parameter_list" for child in node.children)
    is_function_declarator = any(child.type == "function_declarator" for child in node.children)
    return not (has_parameters or is_function_declarator)

def remove_pseudo_declaration(pseudo_code):
    # C_LANGUAGE = tree_sitter.Language(tree_sitter_cpp.language())
    # # Initialize Tree-sitter parser
    # parser = tree_sitter.Parser(C_LANGUAGE)

    # OLD VERSION
    C_LANGUAGE = tree_sitter.Language(tree_sitter_cpp.language(), 'cpp')
    parser = tree_sitter.Parser()
    parser.set_language(C_LANGUAGE)

    def traverse_tree(node, to_remove=[], depth=0):
        if depth > 10:
            return
        if node.type == 'declaration' and is_variable_declaration(node):
            to_remove.append([node.start_byte, node.end_byte])
            return
        elif node.type == 'comment':
            to_remove.append([node.start_byte, node.end_byte])
            return
        for child in node.children:
            traverse_tree(child, to_remove, depth+1)

    tree = parser.parse(bytes(pseudo_code, "utf-8"))
    to_remove = []
    traverse_tree(tree.root_node, to_remove=to_remove)
    to_remove = sorted(to_remove, key=lambda x: x[0], reverse=True)
    code = pseudo_code
    for start_byte, end_byte in to_remove:
        if start_byte == 0:
            continue
        code = code[:start_byte] + code[end_byte:]
    cur_code = ''
    for line in code.split('\n'):
        if len(line.strip()) == 0:
            continue
        cur_code += line + '\n'
    return cur_code


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Embed pseudo code with jina')
    parser.add_argument('-m', '--model_path', action="store",
                        required=True)
    parser.add_argument('-i', '--input', action="store",
                        required=True)
    args = parser.parse_args()
    model_path = args.model_path

    tokenizer = AutoTokenizer.from_pretrained(model_path)
    model = AutoModel.from_pretrained(model_path, trust_remote_code=True).cuda()
    model = torch.nn.DataParallel(model).cuda()
    model.max_seq_length = 1024

    # 310 for 80G
    # 256 for 32G
    infer_batch_size = 310 * len(os.environ["CUDA_VISIBLE_DEVICES"].split(','))

    to_infer = []
    for root, dirs, files in os.walk(args.input):
        for file in files:
            if not file.endswith('_pseudo.json'):
                continue
            if file.replace('_pseudo.json', '_jina_embedding.pkl') in files:
                continue
            to_infer.append(os.path.join(root, file))
    last_d = None
    for file in tqdm(to_infer, total=len(to_infer)):
        d = os.path.dirname(file)
        if d != last_d:
            print(f'Handling {d}...')
            last_d = d
        with open(file, 'r') as f:
            data = json.load(f)
        
        fvas = list(data.keys())
        names = []
        embeddings = []
        pseudo_codes = []
        for fva in fvas:
            code = remove_pseudo_declaration(data[fva]['decompiled_code'])
            pseudo_codes.append(code)
            names.append(data[fva]['name'])
        input_ids = []
        attention_mask = []
        embeddings = []
        for i in range(0, len(pseudo_codes), infer_batch_size):
            res = tokenizer(pseudo_codes[i:i+infer_batch_size], padding='max_length', truncation=True, max_length=1024, return_tensors='pt')
            input_ids = res['input_ids']
            attention_mask = res['attention_mask']
            input_ids = torch.Tensor(np.array(input_ids)).long().cuda()
            attention_mask = torch.Tensor(np.array(attention_mask)).int().cuda()
            with torch.no_grad():
                output = model(input_ids, attention_mask=attention_mask)
                e = mean_pooling(output, attention_mask)
                e = F.normalize(e, p=2, dim=1)
                embeddings.extend(e.detach().cpu().numpy().tolist())
            torch.cuda.empty_cache()
        with open(file.replace('_pseudo.json', '_jina_embedding.pkl'), 'wb') as f:
            pickle.dump([fvas, names, embeddings], f)
