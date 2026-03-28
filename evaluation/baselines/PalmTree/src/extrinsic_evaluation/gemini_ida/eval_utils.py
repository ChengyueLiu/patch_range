from model import UniSkip, Encoder
from data_loader import DataLoader
from vocab import load_dictionary
from config import *
from torch import nn
import torch.nn.functional as F

from torch.autograd import Variable
import torch
import re
numpy = True
import numpy as np
import pickle
import vocab_pt



class UsableTransformer:
    def __init__(self, model_path, vocab_path):
        print("Loading Vocab", vocab_path)
        self.vocab = vocab_pt.WordVocab.load_vocab(vocab_path)
        print("Vocab Size: ", len(self.vocab))
        self.model = torch.load(model_path)
        self.model.eval()
        if USE_CUDA:
            self.model.cuda()


    def encode(self, text, output_option='lst'):

        segment_label = []
        sequence = []
        for t in text:
            l = (len(t.split(' '))+2) * [1]
            s = self.vocab.to_seq(t)
            # print(t, s)
            s = [3] + s + [2]
            if len(l) > 20:
                segment_label.append(l[:20])
            else:
                segment_label.append(l + [0]*(20-len(l)))
            if len(s) > 20:
                 sequence.append(s[:20])
            else:
                sequence.append(s + [0]*(20-len(s)))
         
        segment_label = torch.LongTensor(segment_label)
        sequence = torch.LongTensor(sequence)

        if USE_CUDA:
            sequence = sequence.cuda()
            segment_label = segment_label.cuda()

        encoded = self.model.forward(sequence, segment_label)
        result = torch.mean(encoded.detach(), dim=1)

        del encoded
        if USE_CUDA:
            if numpy:
                return result.data.cpu().numpy()
            else:
                return result.to('cpu')
        else:
            if numpy:
                return result.data.numpy()
            else:
                return result