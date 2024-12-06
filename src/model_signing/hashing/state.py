"""Machinery for computing digests for a single state.

Example usage for `SimpleStateHasher`:
```python
>>> with open("/tmp/state", "w") as f:
...     f.write("abcd")
>>> hasher = SimpleStateHasher("/tmp/state", SHA256())
>>> digest = hasher.compute()
>>> digest.digest_hex
'88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589'
```
"""

import collections

from typing_extensions import override

from model_signing.hashing import hashing
import json
import torch
from cuda.bindings import driver, nvrtc


class StateHasher(hashing.HashEngine):
    """Generic state hash engine.

    This class is intentionally empty (and abstract, via inheritance) to be used
    only as a type annotation (to signal that API expects a hasher capable of
    hashing states, instead of any `HashEngine` instance).
    """

    pass


class SimpleStateHasher(StateHasher):
    """Simple state hash engine that computes the digest iteratively.

    To compute the hash of a state, we read the state exactly once, including for
    very large states that don't fit in memory. States are read in chunks and each
    chunk is passed to the `update` method of an inner
    `hashing.StreamingHashEngine`, instance. This ensures that the state digest
    will not change even if the chunk size changes. As such, we can dynamically
    determine an optimal value for the chunk argument.
    """

    def __init__(
        self,
        state: collections.OrderedDict,
        content_hasher: hashing.StreamingHashEngine,
        *,
        chunk_size: int = 8192,
        digest_name_override: str | None = None,
    ):
        """Initializes an instance to hash a state with a specific `HashEngine`.

        Args:
            state: The state to hash. Use `set_state` to reset it.
            content_hasher: A `hashing.StreamingHashEngine` instance used to
              compute the digest of the state.
            chunk_size: The amount of state to read at once. Default is 8KB. A
              special value of 0 signals to attempt to read everything in a
              single call.
            digest_name_override: Optional string to allow overriding the
              `digest_name` property to support shorter, standardized names.
        """
        if chunk_size < 0:
            raise ValueError(
                f"Chunk size must be non-negative, got {chunk_size}."
            )

        self._state = state
        self._content_hasher = content_hasher
        self._chunk_size = chunk_size
        self._digest_name_override = digest_name_override

    def set_state(self, state: collections.OrderedDict) -> None:
        """Redefines the state to be hashed in `compute`."""
        self._state = state

    @property
    @override
    def digest_name(self) -> str:
        if self._digest_name_override is not None:
            return self._digest_name_override
        return f"state-{self._content_hasher.digest_name}"

    @override
    def compute(self) -> hashing.Digest:
        self._content_hasher.reset()

        for v in self._state.values():
            v = v.flatten()
            if not hasattr(self, '_buffer'):
                self._buffer = v
            else:
                self._buffer = torch.cat((self._buffer, v))
        print(self._buffer.nbytes)
        return

        b = 0
        while (b < len(dictBytes)):
            end = min(b+self._chunk_size, len(dictBytes))
            self._content_hasher.update(dictBytes[b:end])
            b += self._chunk_size

        digest = self._content_hasher.compute()
        return hashing.Digest(self.digest_name, digest.digest_value)

    @property
    @override
    def digest_size(self) -> int:
        """The size, in bytes, of the digests produced by the engine."""
        return self._content_hasher.digest_size
