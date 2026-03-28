##############################################################################
#                                                                            #
#  Code for the USENIX Security '22 paper:                                   #
#  How Machine Learning Is Solving the Binary Function Similarity Problem.   #
#                                                                            #
#  MIT License                                                               #
#                                                                            #
#  Copyright (c) 2019-2022 Cisco Talos                                       #
#                                                                            #
#  Permission is hereby granted, free of charge, to any person obtaining     #
#  a copy of this software and associated documentation files (the           #
#  "Software"), to deal in the Software without restriction, including       #
#  without limitation the rights to use, copy, modify, merge, publish,       #
#  distribute, sublicense, and/or sell copies of the Software, and to        #
#  permit persons to whom the Software is furnished to do so, subject to     #
#  the following conditions:                                                 #
#                                                                            #
#  The above copyright notice and this permission notice shall be            #
#  included in all copies or substantial portions of the Software.           #
#                                                                            #
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,           #
#  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF        #
#  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND                     #
#  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE    #
#  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION    #
#  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION     #
#  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.           #
#                                                                            #
#  Implementation of the models based on Graph Neural Network (GNN)          #
#    and Structure2vec (s2v).                                                #
#                                                                            #
##############################################################################

import json
import math
import pandas as pd
import os

from .pair_factory_base import PairFactoryBase
from .pair_factory_utils import *
from tqdm import tqdm

import logging

log = logging.getLogger("s2v")


class PairFactoryInference(PairFactoryBase):
    def __init__(
        self,
        func_path,
        feat_path,
        batch_size,
        features_type,
        network_type,
        max_num_vertices,
        length_raw_features,
    ):
        """
        Args
            func_path: CSV file with function pairs
            feat_path: JSON file with function features
            batch_size: size of the batch for each iteration
            features_type: used to select the appropriate decoder and data
            max_num_vertices: maximum number of nodes in the adjancey matrix
            length_raw_features: maximum number of raw features for each BB
        """
        if batch_size <= 0 or batch_size % 2 != 0:
            raise SystemError("Batch size must be even and >= 0")

        self._batch_size = batch_size
        log.info("Batch size (inference): {}".format(self._batch_size))

        self._max_num_vertices = max_num_vertices
        self._network_type = network_type

        self._ftype = features_type
        self._length_raw_features = length_raw_features

        # Based on the type of model/features used use a different decoder
        self._decoder = str_to_np
        if self._ftype == "asm":
            self._decoder = str_to_matrix
        # if self._ftype == "opc":
        #     self._decoder = str_to_scipy_sparse

        log.debug("Reading {}".format(func_path))
        self._func = pd.read_csv(func_path)
        p = func_path.replace('_gemini_pairs.csv', '_digraph_num.json')
        self._fdict = {os.path.basename(p.replace('_digraph_num.json', '.i64')):{}}
        if os.path.exists(p):
            with open(p) as gfd_in:
                d = json.load(gfd_in)
                new_d = {}
                for fva in d:
                    new_d[int(fva, 16)] = d[fva]
                self._fdict[os.path.basename(p.replace('_digraph_num.json', '.i64'))] = new_d



        # Load function features
        # self._fdict = {}
        # for root, dirs, files in os.walk(feat_path):
        #     for file in files:
        #         if file.endswith('digraph_num.json'):
        #             p = os.path.join(root, file)
        #             with open(p) as gfd_in:
        #                 d = json.load(gfd_in)
        #                 new_d = {}
        #                 for fva in d:
        #                     new_d[int(fva, 16)] = d[fva]
        #                 self._fdict[os.path.basename(p.replace('_digraph_num.json', '.i64'))] = new_d

        # Initialize the iterator
        self._get_next_pair_it = self._get_next_pair()

        # Number of function pairs
        self._num_func_pairs = self._func.shape[0]
        log.info("Num func pairs (inference): {}".format(self._num_func_pairs))

        # _get_next_pair() returns a pair of functions
        # _batch_size must be even and >= 2
        # _num_batches is the number of iterations to cover the input data
        # Example:
        #   * 100 functions. Batch_size = 20; 5 iterations
        #   * 100 functions. Batch_size = 16; 7 iterations
        self._num_batches = math.ceil(self._num_func_pairs / self._batch_size)
        log.info("Num batches (inference): {}".format(self._num_batches))
        self.cache = {}
        self.not_found = 0

    def _get_next_pair(self):
        """The function implements an infinite loop over the input data."""
        while True:
            log.info("(Re-)initializing the iterators")
            # (Re-)initialize the iterators
            iterator = self._func.iterrows()

            for _ in range(self._num_func_pairs):
                # Get the next row
                r = next(iterator)[1]
                while r['fva_1'] not in self._fdict[os.path.basename(r['idb_path_1'])] or r['fva_2'] not in self._fdict[os.path.basename(r['idb_path_2'])]:
                    r = next(iterator)[1]
                    self.not_found += 1
                    print(self.not_found, 'functions not found')


                def get_adj_and_fea(idb_path, fva):
                    # if idb_path in self.cache:
                    #     if fva in self.cache[idb_path]:
                    #         return self.cache[idb_path][fva][0], self.cache[idb_path][fva][1]
                    # else:
                    #     self.cache[idb_path] = {}
                    idb_path = os.path.basename(idb_path)
                    fdict = self._fdict[idb_path][fva]
                    adj_mat = str_to_scipy_sparse(fdict['adj_mat'])
                    fea_mat = self._decoder(fdict["features_mat"])
                    # self.cache[idb_path][fva] = [adj_mat, fea_mat]
                    return adj_mat, fea_mat
                adj_l, fea_l = get_adj_and_fea(r['idb_path_1'], r['fva_1'])
                adj_r, fea_r = get_adj_and_fea(r['idb_path_2'], r['fva_2'])
                # fd_l = self._fdict[r["idb_path_1"]][r["fva_1"]]
                # fd_r = self._fdict[r["idb_path_2"]][r["fva_2"]]
                

                if self._ftype != "none":
                    yield (
                        (
                            # str_to_scipy_sparse(fd_l["adj_mat"]),
                            # str_to_scipy_sparse(fd_r["adj_mat"]),
                            adj_l,
                            adj_r
                        ),
                        (
                            # self._decoder(fd_l["features_mat"]),
                            # self._decoder(fd_r["features_mat"]),
                            fea_l,
                            fea_r
                        ),
                        (
                            r['idb_path_1'], r['fva_1'],
                            r['idb_path_2'], r['fva_2'],
                        )
                    )
                else:
                    yield (
                        (
                            # str_to_scipy_sparse(fd_l["adj_mat"]),
                            # str_to_scipy_sparse(fd_r["adj_mat"]),
                            adj_l,
                            adj_r
                        ),
                        (
                            # No features
                            np.ones(
                                (self._length_raw_features, self._max_num_vertices),
                                dtype=np.float32,
                            ),
                            np.ones(
                                (self._length_raw_features, self._max_num_vertices),
                                dtype=np.float32,
                            ),
                        ),
                        (
                            r['idb_path_1'], r['fva_1'],
                            r['idb_path_2'], r['fva_2'],
                        )
                    )

    def pairs(self):
        """Yields batches of pair data."""
        for _ in tqdm(range(self._num_batches), total=self._num_batches):
            # Store graphs, features, and lengths for the left pairs
            g_list_l, f_list_l, len_list_l = list(), list(), list()
            # ... and right pairs
            g_list_r, f_list_r, len_list_r = list(), list(), list()

            pair_infos = list()
            for _ in range(self._batch_size):
                # Get the next positive and negative pair
                gpair, fpair, pair_info = next(self._get_next_pair_it)
                while gpair is None:
                    gpair, fpair, pair_info = next(self._get_next_pair_it)
                pair_infos.append(pair_info)

                # Pad the features
                ft_pos_l, len_pos_l = pad_features_matrix(
                    fpair[0], self._length_raw_features
                )
                ft_pos_r, len_pos_r = pad_features_matrix(
                    fpair[1], self._length_raw_features
                )

                g_list_l.append(gpair[0]), g_list_r.append(gpair[1])
                f_list_l.append(ft_pos_l), f_list_r.append(ft_pos_r)
                len_list_l.append(len_pos_l), len_list_r.append(len_pos_r)

            functions_data = pack_batch(
                f_list_1=f_list_l,
                f_list_2=f_list_r,
                adj_list_1=g_list_l,
                adj_list_2=g_list_r,
                len_list_1=len_list_l,
                len_list_2=len_list_r,
                max_num_vertices=self._max_num_vertices,
                network_type=self._network_type,
            )

            yield functions_data, pair_infos
