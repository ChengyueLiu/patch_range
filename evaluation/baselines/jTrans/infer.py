import os
os.environ["CUDA_VISIBLE_DEVICES"] = "0,1"
from transformers import BertTokenizer, BertForMaskedLM, BertModel
from tokenizer import *
import pickle
from torch.utils.data import DataLoader
import torch
import torch.nn as nn
import numpy as np
from tqdm import tqdm
from data import help_tokenize, load_paired_data,FunctionDataset_CL
from transformers import AdamW
import torch.nn.functional as F
import argparse
import wandb
import logging
import sys
import time
import data
WANDB = True

def get_logger(name):
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', filename=name)
    logger = logging.getLogger(__name__)
    s_handle = logging.StreamHandler(sys.stdout)
    s_handle.setLevel(logging.INFO)
    s_handle.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(filename)s[:%(lineno)d] - %(message)s"))
    logger.addHandler(s_handle)
    return logger

class BinBertModel(BertModel):
    def __init__(self, config, add_pooling_layer=True):
        super().__init__(config)
        self.config = config
        self.embeddings.position_embeddings=self.embeddings.word_embeddings
from datautils.playdata import DatasetBase as DatasetBase

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="jTrans-EvalSave")
    parser.add_argument("--model_path", type=str, default='./models/jTrans-finetune', help="Path to the model")
    parser.add_argument("--dataset_path", type=str, default='./BinaryCorp/small_test', help="Path to the dataset")
    parser.add_argument("--tokenizer", type=str, default='./jtrans_tokenizer/')

    args = parser.parse_args()

    from datetime import datetime
    now = datetime.now() # current date and time
    TIMESTAMP="%Y%m%d%H%M"
    tim = now.strftime(TIMESTAMP)
    logger = get_logger(f"embedding-{TIMESTAMP}")
    logger.info(f"Loading Pretrained Model from {args.model_path} ...")
    model = BinBertModel.from_pretrained(args.model_path)
    total_params = sum(p.numel() for p in model.parameters())
    print(f"Number of parameters: {total_params}")

    model.eval()
    model = model.cuda()
    model = torch.nn.DataParallel(model).cuda()
    # device = torch.device("cuda")
    # model.to(device)

    logger.info("Done ...")
    tokenizer = BertTokenizer.from_pretrained(args.tokenizer)
    logger.info("Tokenizer Done ...")
   
    logger.info("Preparing Datasets ...")

    to_handle = []
    for root, dirs, files in os.walk(args.dataset_path):
        for file in files:
            if file.endswith('jtrans_fea.pkl'):
                out_f = file.replace('jtrans_fea.pkl', 'jtrans_embedding.pkl')
                if not os.path.exists(os.path.join(root, out_f)):
                    to_handle.append(os.path.join(root, file))
    batch_size = 128
    for pkl in tqdm(to_handle, total=len(to_handle)):
        try:
            with open(pkl, 'rb') as f:
                d = pickle.load(f)
        except:
            print('[!!!]', pkl, 'load failed.')
            continue

        res = []
        fvas = []
        func_strs = []
        embeds = []
        for k,v in d.items():
            fva, asm_list, rawbytes_list, cfg, bai_feature = v
            func_str = data.gen_funcstr(v, convert_jump=True)
            fvas.append(fva)
            func_strs.append(func_str)
        
        for i in range(0, len(fvas), batch_size):
            batch_fvas = fvas[i:i+batch_size]
            batch_fstrs = func_strs[i:i+batch_size]
            ret1=tokenizer(batch_fstrs, add_special_tokens=True,max_length=512,padding='max_length',truncation=True,return_tensors='pt') #tokenize them
            seq1=ret1['input_ids']
            mask1=ret1['attention_mask']
            input_ids1, attention_mask1= seq1.cuda(),mask1.cuda()
            output=model(input_ids=input_ids1,attention_mask=attention_mask1)
            anchor=output.pooler_output
            embeddings=anchor.detach().cpu().numpy()
            embeds.extend(embeddings)
        names = ['' for _ in range(len(fvas))]
        embeds = embeds[:len(fvas)]
        res = [fvas, names, embeds]
        with open(pkl.replace('jtrans_fea.pkl', 'jtrans_embedding.pkl'), 'wb') as f:
            pickle.dump(res, f)


    # ft_valid_dataset=FunctionDataset_CL(tokenizer,args.dataset_path,None,True,opt=['O0', 'O1', 'O2', 'O3', 'Os'], add_ebd=True, convert_jump_addr=True)
    # for i in tqdm(range(len(ft_valid_dataset.datas))):
    #     pairs=ft_valid_dataset.datas[i]
    #     for j in ['O0','O1','O2','O3','Os']:
    #         if ft_valid_dataset.ebds[i].get(j) is not None:
    #             idx=ft_valid_dataset.ebds[i][j]
    #             ret1=tokenizer([pairs[idx]], add_special_tokens=True,max_length=512,padding='max_length',truncation=True,return_tensors='pt') #tokenize them
    #             seq1=ret1['input_ids']
    #             mask1=ret1['attention_mask']
    #             input_ids1, attention_mask1= seq1.cuda(),mask1.cuda()
    #             output=model(input_ids=input_ids1,attention_mask=attention_mask1)
    #             anchor=output.pooler_output
    #             ft_valid_dataset.ebds[i][j]=anchor.detach().cpu()

    # logger.info("ebds start writing")
    # pickle.dump(ft_valid_dataset.ebds,fi)
    # fi.close()

