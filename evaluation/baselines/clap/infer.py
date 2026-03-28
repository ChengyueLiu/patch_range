import os
os.environ["CUDA_VISIBLE_DEVICES"] = "0,1"
import torch
import pickle
from transformers import AutoModel, AutoTokenizer
import argparse
import json
import tqdm
import pandas as pd
import numpy as np

parser = argparse.ArgumentParser(description='Clap infer.')
parser.add_argument('-i', '--input_path', action="store", help='Path to the input asm jsons',
                    required=True)
args = parser.parse_args()

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
asm_tokenizer = AutoTokenizer.from_pretrained("hustcw/clap-asm",
                                              trust_remote_code=True,
                                              max_length=1024,
                                              truncation=True,
                                              padding=True
                                              )
asm_encoder = AutoModel.from_pretrained("hustcw/clap-asm",
                                        trust_remote_code=True,
                                        max_length=1024).cuda()
asm_encoder = torch.nn.DataParallel(asm_encoder).cuda()
asm_encoder.max_length=1024


to_handle = []
for root, dirs, files in os.walk(args.input_path):
    for file in files:
        if file.endswith('_clap_asm.json'):
            outp = os.path.join(root, file).replace('_clap_asm.json', '_clap_asm.pkl')
            if not os.path.exists(outp):
                to_handle.append(os.path.join(root, file))

batch_size = 800
# batch_size = 300
            
for file in tqdm.tqdm(to_handle, total=len(to_handle)): 
    outp = file.replace('_clap_asm.json', '_clap_asm.pkl')

    print('Handling', file)
    with open(file, 'r') as f:
        d = json.load(f)
        fvas = []
        asms = []
        for fva in d.keys():
            if len(d[fva]) >= 5:
                fvas.append(fva)
                asms.append(d[fva])
            
        asm_embeddings = []
        # for i in tqdm.tqdm(range(0, len(asms), batch_size), total=int(len(asms)/batch_size)+1):
        #     asm_inputs = asm_tokenizer(asms[i:i+batch_size], padding=True, return_tensors="pt").to(device)
        #     asm_embeddings += asm_encoder(**asm_inputs)
        for i in tqdm.tqdm(range(0, len(asms), batch_size), total=int(len(asms)/batch_size) + 1):
            batch_asms = asms[i:i + batch_size]
            asm_inputs = asm_tokenizer(batch_asms, padding=True, return_tensors="pt").to(device)
            with torch.no_grad():
                batch_embeddings = asm_encoder(**asm_inputs)
            for e in batch_embeddings:
                asm_embeddings.append(e.cpu().numpy())
            torch.cuda.empty_cache()
        names = ["" for _ in range(len(fvas))]
        results = [fvas, names, asm_embeddings]
        with open(outp, 'wb') as f:
            pickle.dump(results, f)

