#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Siamese graph embedding implementaition using tensorflow

By:
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import os
import pickle as pkl
import time
import random
import nltk
from tqdm import tqdm
import pandas as pd
# os.environ["CUDA_VISIBLE_DEVICES"]="-1"

import matplotlib.pyplot as plt
import numpy as np
import tensorflow as tf
from scipy.linalg import block_diag
from sklearn import metrics
# from embedding import Embedding
from dataset import BatchGenerator
# local library%
from siamese_emb import Siamese

# to use tfdbg
# wrap session object with debugger wrapper

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
flags = tf.app.flags
FLAGS = flags.FLAGS

flags.DEFINE_integer('vector_size',128, "Vector size of acfg")
flags.DEFINE_integer('emb_size', 64, "Embedding size for acfg")
flags.DEFINE_float('learning_rate', 0.0001, "Learning Rate for Optimizer")
flags.DEFINE_string('data_file', 'train.pickle', "Stores the train sample after preprocessing")
flags.DEFINE_string('test_file', 'test.pickle', "Stores the test sample after preprocessing")
flags.DEFINE_integer('T', 5, "Number of time to be interated while embedding generation")
flags.DEFINE_string('emb_type', 'mlm_only', "Embedding type")

FILTER_SIZE = 2


def get_some_embedding(it, cnt=35):
    acfg_mat = []
    acfg_nbr_mat = []
    acfg_length_list = []
    mul_mat = []
    func_name_list = []

    while len(func_name_list) < cnt:
        try:
            data = next(it)
        # data = it
        except StopIteration:
            break
        func_name = data[0]
        acfg = data[1]
        if len(acfg) < FILTER_SIZE:
            continue
        acfg_nbr = data[2]
        acfg_length = data[3]

        func_name_list.append(func_name)
        acfg_mat.append(acfg)
        acfg_length_list.append(acfg_length)
        acfg_nbr_mat.append(acfg_nbr)
        mul_mat.append(np.ones(len(acfg_nbr)))
    if len(mul_mat) != 0:
        # acfg_mat = np.vstack(acfg_mat)
        acfg_mat = np.concatenate(acfg_mat)
        acfg_nbr_mat = block_diag(*acfg_nbr_mat)
        mul_mat = block_diag(*mul_mat)
    return acfg_mat, acfg_nbr_mat, acfg_length_list,  mul_mat, func_name_list


class Training:
    def __init__(self):
        self.g_test_similarity = self.test_similarity_internal()

    def test_similarity_internal(self):
        self.funca = tf.placeholder(tf.float32, (None, None))
        self.funcb = tf.placeholder(tf.float32, (None, None))

        mul = tf.matmul(self.funca, self.funcb, transpose_b=True)
        na = tf.norm(self.funca, axis=1, keepdims=True)
        nb = tf.norm(self.funcb, axis=1, keepdims=True)
        return mul / tf.matmul(na, nb, transpose_b=True)

    def test_similarity(self, sess, funca, funcb):
        # funca: embeddings of list a
        # funcb : embeddings of list b
        # ret: predicted value
        return sess.run(self.g_test_similarity, feed_dict={self.funca: funca, self.funcb: funcb})


def test_siamese(num_of_iterations):
    # Training part
    print("starting graph def")
    train_dirs = [
        '/dataset/full_dataset/stripped/noinline/xz',
        '/dataset/full_dataset/stripped/noinline/nmap',
        '/dataset/full_dataset/stripped/noinline/openldap',
        '/dataset/full_dataset/stripped/noinline/curl',
        '/dataset/full_dataset/stripped/noinline/xerces_c',
        '/dataset/full_dataset/stripped/noinline/sqlite',
        '/dataset/full_dataset/stripped/noinline/ImageMagick',
        '/dataset/full_dataset/stripped/noinline/fmt'
    ]
    with tf.Graph().as_default():
        # init class
        siamese = Siamese()
        # data_gen = BatchGenerator(r'/home/administrator/zixiang/gemini/{}/train/*.ida'.format(FLAGS.emb_type,FLAGS.emb_type), FILTER_SIZE)

        global_step = tf.Variable(0, name="global_step", trainable=False)
        print("siamese model  object initialized")

        

        print("started session")
        sess = tf.Session(config=tf.ConfigProto(gpu_options=tf.GPUOptions(per_process_gpu_memory_fraction=0.5)))

        saver = tf.train.Saver()
        with sess.as_default() as sess:

            # can use other optimizers
            optimizer = tf.train.AdamOptimizer(FLAGS.learning_rate)
            
            # optimizer = tf.train.AdamOptimizer(FLAGS.learning_rate)
            train_op = optimizer.minimize(siamese.loss)
            init_op = tf.global_variables_initializer()
            print("defined training operations")
            print("initializing global variables")

            sess.run(init_op)
            # model saved path
            SAVEPATH = "./model/model.ckpt"

            #e_train_start)
            # evalution part
            saver.restore(sess, SAVEPATH)

            print("generating embedding for test samples")
            emb_list = []
            name_list = []
            test_list = []
            test_dirs = [
                '/dataset/full_dataset/stripped/noinline/unrar',
                '/dataset/full_dataset/stripped/noinline/openssl',
                '/dataset/full_dataset/stripped/noinline/zeromq',
                '/dataset/full_dataset/stripped/noinline/json',
                '/dataset/full_dataset/stripped/noinline/leveldb',
                '/dataset/full_dataset/stripped/noinline/libwebp',
                '/dataset/full_dataset/stripped/noinline/libtiff',
                '/dataset/full_dataset/stripped/noinline/PuTTy'
            ]
            # data_gen = BatchGenerator(r'/home/administrator/zixiang/gemini/{}/test/*.ida'.format(FLAGS.emb_type,FLAGS.emb_type), FILTER_SIZE)   
            # data_gen = BatchGenerator(test_dirs, FILTER_SIZE)
            # for k, v in data_gen.train_sample.items():
            #     if len(v) >= 2:
            #         rd = random.sample(v, 2)
            #         test_list.extend(rd)
            # it = iter(test_list)
            emb_func = [siamese.get_embedding()]
            to_handle = []
            for test_dir in test_dirs:
                for root, dirs, files in os.walk(test_dir):
                    for file in files:
                        if file.endswith('_palmtree_fea.pkl'):
                            if os.path.exists(os.path.join(root, file.replace('_palmtree_fea.pkl', '_pt_embedding.pkl'))):
                                continue
                            to_handle.append(os.path.join(root, file))
            

            
            for fea_pkl in tqdm(to_handle):
                acfgs = pkl.load(open(fea_pkl, 'rb'))
                func_list = pd.read_csv(fea_pkl.replace('_palmtree_fea.pkl', '_func_list.csv'))
                fva_dict = {}
                for i, r in func_list.iterrows():
                    fva_dict[r['func_name']] = hex(r['fva'])
                
                    
                fvas = []
                acfg_mat = []
                acfg_nbr_mat = []
                acfg_length_list = []
                mul_mat = []
                func_name_list = []
                not_found = []
                for acfg in acfgs.raw_graph_list:
                    # if len(reduce(operator.add, acfg.fv_list)) < self.filter_size:
                    fvec_list = []
                    fsize_list = []
                    func_name = acfg.funcname
                    fva = None
                    if func_name in fva_dict:
                        fva = fva_dict[func_name]
                    elif func_name.startswith('sub_'):
                        fva = '0x' + func_name[4:].lower()
                    else:
                        not_found.append(func_name)
                        continue

                    for fv in acfg.fv_list:
                        fvec_list.append([fv])
                        if FLAGS.emb_type != 'org': 
                            fsize_list.append(len(fv))
                        else:
                            fsize_list.append(1)

                    # converting to matrix form
                    if FLAGS.emb_type == "manual": 
                        acfg_m = np.array(fvec_list)
                    else:
                        acfg_m = np.concatenate(fvec_list)
                    num_nodes = len(fsize_list)
                    if num_nodes == 0:
                        continue
                    acfg_nbr = np.zeros((num_nodes, num_nodes))
                    
                    for edge in acfg.edge_list:
                        acfg_nbr.itemset((edge[0], edge[1]), 1)
                        acfg_nbr.itemset((edge[1], edge[0]), 1)

                    # self.train_sample[func_name].append((func_name, acfg_mat, acfg_nbr, fsize_list))
                    func_name_list.append(func_name)
                    fvas.append(fva)
                    acfg_mat.append(acfg_m)
                    acfg_length_list.append(fsize_list)
                    acfg_nbr_mat.append(acfg_nbr)
                    mul_mat.append(np.ones(len(acfg_nbr)))
                print(f'{len(not_found)} / {len(acfgs.raw_graph_list)} functions not found')
                if len(mul_mat) != 0:
                    # acfg_mat = np.vstack(acfg_mat)
                    acfg_mat = np.concatenate(acfg_mat)
                    acfg_nbr_mat = block_diag(*acfg_nbr_mat)
                    mul_mat = block_diag(*mul_mat)
                    
                    embed_list = []
                
                    # infer current pickle
                    idx = 0
                    idy = 0
                    merged_acfg_mat = np.ndarray((acfg_nbr_mat.shape[0], FLAGS.vector_size))
                    if FLAGS.emb_type != "manual" and FLAGS.emb_type != "albert_avg":
                        for length in acfg_length_list:
                            l = len(length)
                            ins = np.expand_dims(acfg_mat[idx: idx+l], axis=0)
                            merged_acfg_mat[idy,:] = np.squeeze(sess.run([siamese.bb_emb], feed_dict={siamese.ins: ins}), axis=0)
                            idy += 1
                            idx += l
                        print(idx, idy, acfg_mat.shape, merged_acfg_mat.shape)
                        x = np.concatenate([merged_acfg_mat, np.transpose(mul_mat)], 1)
                        n = acfg_nbr_mat
                        print(len(x), '-------')
                        for i in range(len(x)):
                            print(x[i][:10])
                            input()
                        embed = sess.run(emb_func, feed_dict={siamese.x: np.concatenate([merged_acfg_mat, np.transpose(mul_mat)], 1),
                                                            siamese.n: acfg_nbr_mat})
                        print(len(embed[0]), embed[0][-10])
                        
                    else:
                        assert(0)
                    embed_list = embed[0]
                    with open(fea_pkl.replace('_palmtree_fea.pkl', '_pt_embedding.pkl'), 'wb') as f:
                        print(fea_pkl)
                        pkl.dump([fvas, func_name_list, embed_list], f)
                        exit(0)

    

def plot_eval_siamese(total_fp, total_tp):
    plt.figure(1)
    plt.title('ROC')
    plt.plot(total_fp, total_tp, '-', label='ROC')
    plt.legend(loc='lower right')
    plt.xlim([-0.1, 1.1])
    plt.ylim([-0.1, 1.1])
    plt.ylabel('True Positive Rate')
    plt.xlabel('False Positive Rate')
    plt.show()


if __name__ == "__main__":
    test_siamese(100)
    # total_fp, total_tp = train_siamese(100)
    # plot_eval_siamese(total_fp, total_tp)
    # with open('./{}_total_fp.txt'.format(FLAGS.emb_type), 'wb') as f:
    #     pkl.dump(total_fp, f)
    # with open('./{}_total_tp.txt'.format(FLAGS.emb_type), 'wb') as f:
    #     pkl.dump(total_tp, f)
    
    # print(metrics.auc(total_fp, total_tp))
