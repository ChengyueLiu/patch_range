import os
os.environ['CUDA_VISIBLE_DEVICES'] = '2'
import gmn_evaluation
import gen_diff_pools

if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(description='GMN')
    ap.add_argument('-m', '--mode', type=str)
    ap.add_argument('-n', '--neg', type=str)
    args = ap.parse_args()
    # opts = ['xa', 'xb', 'xbcvo', 'xm', 'xab', 'xm100k', 'rw', 'xcv86', 'xo86']
    # opts = ['xm100k']
    opts = ['xbcvom', 'xmm']
    # modes = ['noinline', 'inline']
    modes = [args.mode]
    for mode in modes:
        for opt in opts:
            print(f'Evaluating {opt}')
            dataset = f'gen_dataset/microcode_{mode}_test.pkl'
            similarity = f'/pools_new/{mode}/{mode}_test_{opt}.json'
            pos = f'/pools_new/{mode}/pos-{mode}_test_{opt}.csv'
            neg = f'/pools_new/{mode}/neg-{mode}_test_{opt}.csv'
            # res = f'result/{mode}_test_{opt}_{mode}-gmn_result.csv'
            binsim = gmn_evaluation.BinSim(dataset, similarity, pos, neg)
            binsim.evaluation(1000)
            # binsim = gen_diff_pools.BinSim(dataset, similarity, pos, neg)
            # result = binsim.evaluation(1000)
            # gen_diff_pools.save_result(result, res)
        
        
