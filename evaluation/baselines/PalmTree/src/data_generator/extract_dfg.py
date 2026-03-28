import os
import sys
import subprocess
import time
import argparse

IDA_PATH = '/workspace/idapro-8.3/idat64'
IDA_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'IDA_dfg.py')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate ida database from binaries.')
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
        for input_path in train_dirs:
            for root, dirs, files in os.walk(input_path):
                for file in files:
                    if not file.startswith('x'):
                        continue
                    if file.endswith('.i64') or file.endswith('.idb'):
                        # if not os.path.exists(os.path.join(root, file.replace('.i64', '_palmtree_dfg.txt'))):
                        to_handle.append(os.path.join(root, file))
        while True:
            if len(to_handle) == 0:
                break
            while len(thread_pool) < thread_num and len(to_handle) > 0:
                i64_path = to_handle.pop()
                print([IDA_PATH, '-A', '-Lida_export.log', f'-S{IDA_SCRIPT}', f'-Oidb:{i64_path}', i64_path])
                p = subprocess.Popen([IDA_PATH, '-A', '-Lida_export.log', f'-S{IDA_SCRIPT}', f'-Oidb:{i64_path}', i64_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                thread_pool.append(p)
                print('Remained:', len(to_handle), 'Unfinished:', len(thread_pool))
            for i in range(len(thread_pool)):
                if thread_pool[i].poll() is not None:
                    thread_pool[i] = None
            if None in thread_pool:
                thread_pool.remove(None)
            thread_pool = list(filter(lambda x: x!= None, thread_pool))
            time.sleep(0.2)
        for p in thread_pool:
            p.wait()
    else:
        os.system(' '.join([IDA_PATH, '-A', '-Lida_export.log', f'-S{IDA_SCRIPT}', f'-Oidb:{input_path}', input_path]))