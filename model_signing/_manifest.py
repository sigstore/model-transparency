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

from enum import Enum
from typing import List

import in_toto_attestation.v1.resource_descriptor_pb2 as rdpb
from sigstore import dsse

class DigestAlgorithm(Enum):
    SHA256_P1 = 1

    def __str__(self):
        return str(self.name).replace("_", "-").lower()
    @staticmethod
    def from_string(s: str):
        return DigestAlgorithm[s.replace("-", "_")]

class Hashed:
    algorithm: DigestAlgorithm
    digest: bytes
    def __init__(self, algorithm_: DigestAlgorithm, digest_: bytes):
        self.algorithm = algorithm_
        self.digest = digest_

class PathMetadata:
    hashed: Hashed
    path: str
    def __init__(self, path_: str, hashed_: Hashed):
        self.path = path_
        self.hashed = hashed_

class Manifest:
    paths: PathMetadata
    predicate_type: str
    def __init__(self, paths: [PathMetadata]):
        self.paths = paths
        self.predicate_type = "sigstore.dev/model-transparency/manifest/v1"   

    def verify(self, verified_manifest: any) -> None:
        # The manifest is the one constructed from disk and is untrusted.
        # The statement is from the verified bundle and is trusted.
        # Verify the type and version.
        predicateType = verified_manifest["predicateType"]
        if predicateType != self.predicate_type:
            raise ValueError(f"invalid predicate type: {predicateType}")
        files = verified_manifest["predicate"]["files"]
        if len(self.paths) != len(files):
            raise ValueError(f"mismatch number of files: expected {len(files)}, got {len(self.paths)}")
        for i in range(len(self.paths)):
            actual_path = self.paths[i]
            verified_path = files[i]
            # Verify the path.
            if actual_path.path != verified_path["path"]:
                raise ValueError(f"mismatch path name: expected '{verified_path['path']}'. Got '{actual_path.path}'")
            # Verify the hash name in verified manifest.
            if str(DigestAlgorithm.SHA256_P1) not in verified_path["digest"]:
                raise ValueError(f"unrecognized hash algorithm: {set(verified_path['digest'].keys())}")
            # Verify the hash name in actual path.
            if actual_path.hashed.algorithm != DigestAlgorithm.SHA256_P1:
                raise ValueError(f"internal error: algorithm {str(actual_path.hashed.algorithm)}")
            # Verify the hash value.
            verified_digest = verified_path["digest"][str(actual_path.hashed.algorithm)]
            if actual_path.hashed.digest.hex() != verified_digest:
                raise ValueError(f"mismatch hash for file '{actual_path.path}': expected '{verified_digest}'. Got '{actual_path.hashed.digest.hex()}'")


    def to_intoto_statement(self) -> dsse.Statement:
        # See example at https://github.com/in-toto/attestation/blob/main/python/tests/test_statement.py.
        files: [any] = []
        for _, p in enumerate(self.paths):
            f = {
                "path": p.path,
                "digest": {
                    str(p.hashed.algorithm): p.hashed.digest.hex(),
                },
            }
            files += [f]
        stmt = (
            dsse._StatementBuilder()
            .subjects(
                [dsse._Subject(name="-", digest={"sha256": "-"})]
            )
            .predicate_type(self.predicate_type)
            .predicate(
                {
                    "files": files,
                }
            )
        ).build()
        return stmt
