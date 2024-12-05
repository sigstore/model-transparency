"""Machinery for computing digests for a single model.

Example usage for `SimpleModelHasher`:
```python
>>> with open("/tmp/model", "w") as f:
...     f.write("abcd")
>>> hasher = SimpleModelHasher("/tmp/model", SHA256())
>>> digest = hasher.compute()
>>> digest.digest_hex
'88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589'
```

Example usage for `ShardedModelHasher`, reading only the second part of a model:
```python
>>> with open("/tmp/model", "w") as f:
...     f.write("0123abcd")
>>> hasher = ShardedModelHasher("/tmp/model", SHA256(), start=4, end=8)
>>> digest = hasher.compute()
>>> digest.digest_hex
'88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589'
```

Example usage for `OpenedModelHasher`:
```python
>>> with open("/tmp/model", "w") as f:
...     f.write("abcd")
>>> with open("/tmp/model", "rb") as f:
...     hasher = OpenedModelHasher(f)
...     digest = hasher.compute()
>>> digest.digest_hex
'88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589'
```
"""

import collections

from typing_extensions import override

from model_signing.hashing import hashing


class ModelHasher(hashing.HashEngine):
    """Generic model hash engine.

    This class is intentionally empty (and abstract, via inheritance) to be used
    only as a type annotation (to signal that API expects a hasher capable of
    hashing models, instead of any `HashEngine` instance).
    """

    pass


class SimpleModelHasher(ModelHasher):
    """Simple model hash engine that computes the digest iteratively.

    To compute the hash of a model, we read the model exactly once, including for
    very large models that don't fit in memory. Models are read in chunks and each
    chunk is passed to the `update` method of an inner
    `hashing.StreamingHashEngine`, instance. This ensures that the model digest
    will not change even if the chunk size changes. As such, we can dynamically
    determine an optimal value for the chunk argument.
    """

    def __init__(
        self,
        model: collections.OrderedDict,
        content_hasher: hashing.StreamingHashEngine,
        *,
        chunk_size: int = 8192,
        digest_name_override: str | None = None,
    ):
        """Initializes an instance to hash a model with a specific `HashEngine`.

        Args:
            model: The model to hash. Use `set_model` to reset it.
            content_hasher: A `hashing.StreamingHashEngine` instance used to
              compute the digest of the model.
            chunk_size: The amount of model to read at once. Default is 8KB. A
              special value of 0 signals to attempt to read everything in a
              single call.
            digest_name_override: Optional string to allow overriding the
              `digest_name` property to support shorter, standardized names.
        """
        if chunk_size < 0:
            raise ValueError(
                f"Chunk size must be non-negative, got {chunk_size}."
            )

        self._model = model
        self._content_hasher = content_hasher
        self._chunk_size = chunk_size
        self._digest_name_override = digest_name_override

    def set_model(self, model: collections.OrderedDict) -> None:
        """Redefines the model to be hashed in `compute`."""
        self._model = model

    @property
    @override
    def digest_name(self) -> str:
        if self._digest_name_override is not None:
            return self._digest_name_override
        return f"model-{self._content_hasher.digest_name}"

    @override
    def compute(self) -> hashing.Digest:
        self._content_hasher.reset()

        if self._chunk_size == 0:
            with open(self._model, "rb") as f:
                self._content_hasher.update(f.read())
        else:
            with open(self._model, "rb") as f:
                while True:
                    data = f.read(self._chunk_size)
                    if not data:
                        break
                    self._content_hasher.update(data)

        digest = self._content_hasher.compute()
        return hashing.Digest(self.digest_name, digest.digest_value)

    @property
    @override
    def digest_size(self) -> int:
        """The size, in bytes, of the digests produced by the engine."""
        return self._content_hasher.digest_size
