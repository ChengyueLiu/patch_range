import os
import subprocess
import multiprocessing
import time
from util.pairdata import pairdata
import argparse

IDA_PATH = '/workspace/idapro-8.3/idat64'
IDA_SCRIPT = f"./process.py"

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate ida database from binaries.')
    parser.add_argument('-i', '--input_path', action="store",
                        required=True)
    parser.add_argument('-p', '--process_num', action="store",
                        required=False, default=1)
    args = parser.parse_args()

    thread_num = int(args.process_num)

    thread_pool = []
    input_path = args.input_path
    if os.path.isdir(input_path):
        to_handle = []
        for root, dirs, files in os.walk(input_path):
            for file in files:
                if file.endswith('.i64') or file.endswith('.idb'):
                    if not os.path.exists(os.path.join(root, file.replace('.idb', '_jtrans_fea.pkl').replace('.i64', '_jtrans_fea.pkl'))):
                        to_handle.append(os.path.join(root, file))
        while True:
            if len(to_handle) == 0:
                break
            while len(thread_pool) < thread_num and len(to_handle) > 0:
                i64_path = to_handle.pop()
                print(' '.join([IDA_PATH, '-A', '-Lida_export.log', f'-S{IDA_SCRIPT}', f'-Oidb:{i64_path}', i64_path]))
                p = subprocess.Popen([IDA_PATH, '-A', '-Lida_export.log', f'-S{IDA_SCRIPT}', f'-Oidb:{i64_path}', i64_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                thread_pool.append(p)
                print('Remained:', len(to_handle), 'Unfinished:', len(thread_pool))
            for i in range(len(thread_pool)):
                if thread_pool[i].poll() is not None:
                    thread_pool.pop(i)
                    break
            time.sleep(0.1)
        for p in thread_pool:
            p.wait()
    else:
        os.system(' '.join([IDA_PATH, '-A', '-Lida_export.log', f'-S{IDA_SCRIPT}', f'-Oidb:{input_path}', input_path]))

