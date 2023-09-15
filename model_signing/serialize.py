# Copyright Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing perepo_managerissions and
# limitations under the License.

import hashlib, base64, os
from typing import IO
from multiprocessing import current_process
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures import wait
from multiprocessing import set_start_method
from time import sleep
from pathlib import Path

class Hasher:
    @staticmethod
    def node_header(name: str, ty: str) -> bytes:
        header = ty.encode('utf-8') + b'.' + base64.b64encode(name.encode('utf-8')) + b'.'
        return header

    @staticmethod
    def root_folder(path: Path, content:bytes) -> str:
        return Hasher._node_folder_compute(name="root", content=content)
    
    @staticmethod
    def node_folder(path: Path, content:bytes) -> str:
        return Hasher._node_folder_compute(name=path.name, content=content)

    @staticmethod
    def _node_folder_compute(name: str, content: bytes) -> bytes:
        value = Hasher.node_header(name, "dir") + content
        return hashlib.sha256(value).digest()

    @staticmethod
    def root_file(path: Path, chunk: int) -> bytes:
        return Hasher._node_file_compute(path, b'', chunk)

    @staticmethod
    def node_file(path: Path, chunk: int = 0) -> bytes:
        if not path.is_file():
            raise ValueError(f"path {path} is not a file")
        header = Hasher.node_header(path.name, "file")
        return Hasher._node_file_compute(path, header, chunk)

    @staticmethod
    def _node_file_compute(path: Path, header: bytes, chunk: int) -> bytes:
        h = hashlib.sha256(header)
        with open(path,"rb") as f:
            if chunk == 0:
                all_data = f.read()
                h.update(all_data)
            else:
                # Compute the hash by reading chunk bytes at a time.
                while True:
                    chunk_data = f.read(chunk)
                    if not chunk_data:
                        break
                    h.update(chunk_data)
        return h.digest()

    @staticmethod
    def _node_file_compute_v1(path: Path, header: bytes, start: int, end: int, chunk: int) -> bytes:
        h = hashlib.sha256(header)
        with open(path,"rb") as f:
            f.seek(start)
            # Read all at once.
            if chunk == 0 or chunk >= (end - start):
                content = f.read(end - start)
                print(f"all: {f.name}: {start}-{end}")
                h.update(content)
            else:
                # Compute the hash by reading chunk bytes at a time.
                o_start = 0
                o_end = chunk # chunk is < total number of bytes to read.
                while True:
                    chunk_data = f.read(o_end - o_start)
                    print(f"loop {o_start/chunk}: {f.name}: {start + o_start}-{start + o_end}")
                    # NOTE: len(chunk_data) may be < the request number of bytes (o_end - o_start)
                    # when we reach the EOF.
                    if not chunk_data:
                        break
                    h.update(chunk_data)
                    o_start += chunk
                    o_end += chunk

        return h.digest()

def remove_prefix(text, prefix):
    if text.startswith(prefix):
        return text[len(prefix):]
    return text

def validate_signature_path(model_path: Path, sig_path: Path):
    if model_path.is_file():
        return
    # Note: Only allow top-level folder to have the signature for simplicity.
    if sig_path is not None and sig_path.is_relative_to(model_path) and sig_path.parent != model_path:
        raise ValueError(f"{sig_path} must be in the folder root")

# TODO(): add a context "AI model"?
class Serializer:
    # TODO: use number of vCPUs to split work.
    # We will hash in paralell multiple chunks of pre-defined length
    # 1GB (?) and use threads. We need to devide the chunk size
    # by the number of vCPUs. The main thread will create a list of
    # offsets to hash the file at, and will wait for all to finish.
    @staticmethod
    def serialize_v1(path: Path, chunk: int, signature_path: Path, ignorepaths: [Path] = []) -> bytes:
        # if path.is_file():
        #     return Hasher.root_file(path, chunk)

        # if not path.is_dir():
        #     raise ValueError(f"{str(path)} is not a dir")

        # Validate the signature path.
        validate_signature_path(path, signature_path)
        
        # NOTE: the parent (..) and current directory (.) are not prsent.
        # TODO: cleanup for handle both cases.
        if path.is_file():
            children = [path]
        else:
            children = sorted(path.glob("**/*"))
        
        filtered = []
        total_size = 0
        for child in children:
            if child in ignorepaths:
                continue
            
            if not path.is_file() and not path.is_dir():
                raise ValueError(f"{str(path)} is not a dir or file")

            # The recorded path must *not* contains the folder name,
            # since users may rename it.
            record_path = remove_prefix(str(child), str(path.as_posix()) + os.sep)
            record_size = os.path.getsize(str(child))
            record_type = "file" if child.is_file() else "dir"
            filtered += [(record_path, record_type, record_size)]
            total_size += record_size if record_type == "file" else 0
            #print(record_path, record_size, record_type, total_size)

        # We have the name of files and their sizes.
        # We partition using partition_size.
        partition_size = 1000000000 # 1GB bytes
        print("total_size:", total_size)
        
        # filtered = [("fn1", "file", 110), ("fn2", "file", 130), ("fn3", "file", 91)]
        # total_size = 110 + 130 + 290
        # # TODO: function for this.
        # Small files (<= partition_size) can be hashed in parallel.
        # Larger files (> partition_size) can have each partition hashed in parallel.
        # n_groups = int(total_size / partition_size)
        # n_groups_left = total_size - (n_groups * partition_size)
        # n_groups += n_groups_left
        # #cpu_tasks = [[]]*n_cpu
        grouped_tasks = [[]] * 0
        # print(total_size, len(grouped_tasks))

        curr_file = 0
        curr_bytes = 0
        total_bytes = 0
        while True:
            if curr_file >= len(filtered):
                print("all files processed")
                break
            
            name, typ, size = filtered[curr_file]            
            print(name, typ, size)
            if typ == "dir":
                curr_bytes = 0
                grouped_tasks += [(name, typ, 0, size)]
                #print("", f"dir : keeping cpu {curr_cpu}")
                curr_file += 1
                continue

            # It's a file.
            if size <= curr_bytes and size > 0:
                raise ValueError(f"internal: size={size}, curr_bytes={curr_bytes} for {filtered[curr_file]}")

            start_pos = curr_bytes
            available_bytes = size - start_pos
            if available_bytes < 0:
                raise ValueError(f"internal: available_bytes is {available_bytes}")

            processed_bytes = min(available_bytes, partition_size)
            print("", f"processed_bytes: {processed_bytes}")
            end_pos = curr_bytes + processed_bytes
            curr_bytes += processed_bytes
            total_bytes += processed_bytes
            print("", f"start_pos: {start_pos}, end_pos: {end_pos}, curr_bytes: {curr_bytes}, tot_bytes: {total_bytes}")

            # Record the task.
            grouped_tasks += [(name, typ, start_pos, end_pos)]
            if available_bytes - processed_bytes == 0:
                curr_file += 1
                curr_bytes = 0
                print("", f"curr_file updated to {curr_file}")
            
            
            
        print("grouped_tasks:", grouped_tasks)

        # TODO: need to keep the ordering for split files. Can use start, end offsets
        # We distribute the hashing across n_cpus.
        # We allocate min(n_task, n_cpu). For simplicity, we currently allocate
        # all memory upfront. TODO: respect chunk
        # total_tasks = 0
        # while total_tasks != len(grouped_tasks):
        #     # Submit tasks up to chunk bytes of returned values.
        #     n_tasks = 32*len(grouped_tasks) // chunk 

        #     total_tasks += n_tasks
        all_hashes = [1] * (32*len(grouped_tasks))
        all_hashes[10:12] = [2,2]
        org_len = len(all_hashes)
        #print(bytes(all_hashes))
        #pool = multiprocessing.Pool()
        # https://superfastpython.com/processpoolexecutor-in-python/#How_to_Get_Results_From_Futures
        set_start_method('fork')
        with ProcessPoolExecutor() as ppe:
            # future = ppe.submit(Serializer.task, (0, grouped_tasks))
            # result = future.result()
            futures = [ ppe.submit(Serializer.task, (path, chunk, grouped_tasks[i])) for i in range(len(grouped_tasks)) ]
            print("waiting...")
            # futures = [ppe.submit(task, i) for i in range(2)]
            #_ = wait(futures)
            results = [ f.result() for f in futures ]
            for i in range(len(results)):
                print(i, results[i], len(results[i]), i*32, (i+1)*32)
                all_hashes[i*32:(i+1)*32] = results[i]
            #print(results)
            # print(all_hashes)
            # print("bytes:", bytes(all_hashes))
            # print(len(all_hashes))
            # futures = [ ppe.submit(Serializer.task, (i, grouped_tasks)) for i in range(len(grouped_tasks)) ]
            # print("waiting...")
            # futures = [ppe.submit(task, i) for i in range(2)]
            #_ = wait(futures)
        if len(all_hashes) != org_len:
            raise ValueError(f"internal: {len(all_hashes)} != {org_len}")
        print("last...")
        # TODO: fix / remove header
        return hashlib.sha256(bytes(all_hashes)).digest()

    @staticmethod
    def task(task_info):
        # get the current process
        worker = current_process()
        # report details about the current process
        path, chunk, (name, ty, start_pos, end_pos) = task_info
        print(f'Task {task_info}, worker name={worker.name}, pid={worker.pid}', flush=True)
        if ty == "dir":
            value = Hasher.node_header(name, "dir") + b'empty'
            return hashlib.sha256(value).digest()
        #TODO: verify last position is not included.
        # TODO: make this a function.
        header = ty.encode('utf-8') + b'.' + base64.b64encode(name.encode('utf-8')) + b'.' + f"{start_pos}-{end_pos}".encode('utf-8') + b'.'
        # TODO: that's for dir.
        return Hasher._node_file_compute_v1(path.joinpath(name), header, start_pos, end_pos, chunk)
        # That's for single file.
        #return Hasher._node_file_compute(name, header, chunk)

    @staticmethod
    def serialize_v0(path: Path, chunk: int, signature_path: Path, ignorepaths: [Path] = []) -> bytes:
        if path.is_file():
            return Hasher.root_file(path, chunk)

        if not path.is_dir():
            raise ValueError(f"{str(path)} is not a dir")

        # Validate the signature path.
        validate_signature_path(path, signature_path)

        children = sorted([x for x in path.iterdir() if x != signature_path and x not in ignorepaths])
        # TODO: remove this special case?
        if len(children) == 0:
            return Hasher.root_folder(path, b"empty")

        hash = hashlib.sha256()
        for child in children:
            child_hash = Serializer._serialize_node(child, chunk, " ")
            hash.update(child_hash)
        content = hash.digest()
        return Hasher.root_folder(path, content)
    
    @staticmethod
    def _serialize_node(path: Path, chunk: int, indent = "") -> bytes:
        if path.is_file():
            return Hasher.node_file(path, chunk)

        if not path.is_dir():
            raise ValueError(f"{str(path)} is not a dir")

        children = sorted([x for x in path.iterdir()])
        # TODO: remove this special case?
        if len(children) == 0:
            return Hasher.node_folder(path, b"empty")

        hash = hashlib.sha256()
        for child in children:
            child_hash = Serializer._serialize_node(child, chunk, indent + " ")
            hash.update(child_hash)
        content = hash.digest()
        return Hasher.node_folder(path, content)
