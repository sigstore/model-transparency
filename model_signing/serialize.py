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

import hashlib, base64, json
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

# TODO(): add a context "AI model"?
class Serializer:
    @staticmethod
    def serialize(path: Path, chunk: int, ignorefn: Path = None) -> bytes:
        if path.is_file():
            return Hasher.root_file(path, chunk)

        if not path.is_dir():
            raise ValueError(f"{str(path)} is not a dir")
        
        # Note: Only allow top-level folder to have the signature for simplicity.
        if ignorefn is not None and ignorefn.is_relative_to(path) and ignorefn.parent != path:
            raise ValueError(f"{ignorefn} must be in the folder root")
        
        children = sorted([x for x in path.iterdir() if x != ignorefn])
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
