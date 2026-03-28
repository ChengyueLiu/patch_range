import os
os.environ['CUDA_VISIBLE_DEVICES'] = '3,4'
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader
from torch.autograd import Variable
from config import *
import numpy as np
import bert_pytorch
import palmtree
from palmtree import dataset
from palmtree import trainer
import pickle as pkl

print(palmtree.__file__)
vocab_path = "cdfg_bert_1/vocab"
# train_cfg_dataset = "data/training/cdfg_bert_1/cfg_train.txt"
# train_dfg_dataset = "data/training/cdfg_bert_1/dfg_train.txt"
# test_dataset = "data/training/cdfg_bert_1/test.txt"
test_dataset = None
output_path = "cdfg_bert_1/transformer"
train_path = '/dataset/full_dataset/stripped/noinline'
train_cfg_dataset = 'cfg_train.txt'
train_dfg_dataset = 'dfg_train.txt'
# train_cfg_dataset = '/dataset/full_dataset/stripped/noinline/xz/x86-gcc-6-Os-xz_palmtree_cfg.txt'
# train_dfg_dataset = '/dataset/full_dataset/stripped/noinline/xz/x86-gcc-6-Os-xz_palmtree_dfg.txt'
cfg_f = open(train_cfg_dataset, 'a')
dfg_f = open(train_dfg_dataset, 'a')
for root, dirs, files in os.walk(train_path):
    for file in files:
        if file.endswith('cfg.txt'):
            with open(os.path.join(root, file), 'r') as f:
                cfg_f.write(f.read())
        if file.endswith('dfg.txt'):
            with open(os.path.join(root, file), 'r') as f:
                dfg_f.write(f.read())
cfg_f.close()
dfg_f.close()

with open(train_cfg_dataset, "r", encoding="utf-8") as f1:
    with open(train_dfg_dataset, "r", encoding="utf-8") as f2:
        vocab = dataset.WordVocab([f1, f2], max_size=13000, min_freq=1)

print("VOCAB SIZE:", len(vocab))
vocab.save_vocab(vocab_path)


print("Loading Vocab", vocab_path)
vocab = dataset.WordVocab.load_vocab(vocab_path)
print("Vocab Size: ", len(vocab))
# print(vocab.itos)


print("Loading Train Dataset")
train_dataset = dataset.BERTDataset(train_cfg_dataset, train_dfg_dataset, vocab, seq_len=20,
                            corpus_lines=None, on_memory=True)

print("Loading Test Dataset", test_dataset)
test_dataset = bert_pytorch.dataset.BERTDataset(test_dataset, test_dataset, vocab, seq_len=20, on_memory=True) \
    if test_dataset is not None else None

print("Creating Dataloader")
train_data_loader = DataLoader(train_dataset, batch_size=256, num_workers=10)



test_data_loader = DataLoader(test_dataset, batch_size=256, num_workers=10) \
    if test_dataset is not None else None

print("Building BERT model")
bert = bert_pytorch.BERT(len(vocab), hidden=128, n_layers=12, attn_heads=8, dropout=0.0)

print("Creating BERT Trainer")
trainer = trainer.BERTTrainer(bert, len(vocab), train_dataloader=train_data_loader, test_dataloader=test_data_loader,
                        lr=1e-5, betas=(0.9, 0.999), weight_decay=0.0,
                        with_cuda=True, cuda_devices=[0], log_freq=100)


print("Training Start")
for epoch in range(20):
    trainer.train(epoch)
    trainer.save(epoch, output_path)
#    if test_data_loader is not None:
#        trainer.test(epoch)     
