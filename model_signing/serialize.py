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
    def root_file(path: Path) -> bytes:
        with open(path,"rb") as f:
            content = f.read()
            return content
        raise ValueError("not reachable")

    def root_folder(path: Path, content:bytes) -> str:
        return Hasher._node_compute(name="root", ty="dir", content=content)

    @staticmethod
    def _node_compute(name: str, ty: str, content: bytes) -> bytes:
        value = ty.encode('utf-8') + b'.' + base64.b64encode(name.encode('utf-8')) + b'.' + content
        return hashlib.sha256(value).digest()
    
    @staticmethod
    def node_folder(path: Path, content:bytes) -> bytes:
        return Hasher._node_compute(name=path.name, ty="dir", content=content)

    @staticmethod
    def node_file(path: Path) -> bytes:
        if not path.is_file():
            raise ValueError(f"path {path} is not a file")
        with open(path,"rb") as f:
            content = f.read()
            return Hasher._node_compute(name=path.name, ty="file", content=content)
        raise ValueError("not reachable")

# TODO(): add a context "AI model"?
class Serializer:
    @staticmethod
    def serialize(path: Path, ignorefn: Path = None) -> bytes:
        if path.is_file():
            return Hasher.root_file(path)

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
            child_hash = Serializer._serialize_node(child, " ")
            hash.update(child_hash)
        content = hash.digest()
        return Hasher.root_folder(path, content)
    
    @staticmethod
    def _serialize_node(path: Path, indent = "") -> bytes:
        if path.is_file():
            return Hasher.node_file(path)

        if not path.is_dir():
            raise ValueError(f"{str(path)} is not a dir")

        children = sorted([x for x in path.iterdir()])
        # TODO: remove this special case?
        if len(children) == 0:
            return Hasher.node_folder(path, b"empty")

        hash = hashlib.sha256()
        for child in children:
            child_hash = Serializer._serialize_node(child, indent + " ")
            hash.update(child_hash)
        content = hash.digest()
        return Hasher.node_folder(path, content)
