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
from cuda.bindings import driver, nvrtc, runtime
import numpy as np


def _cudaGetErrorEnum(error):
    if isinstance(error, driver.CUresult):
        err, name = driver.cuGetErrorName(error)
        return name if err == driver.CUresult.CUDA_SUCCESS else "<unknown>"
    elif isinstance(error, nvrtc.nvrtcResult):
        return nvrtc.nvrtcGetErrorString(error)[1]
    else:
        raise RuntimeError('Unknown error type: {}'.format(error))


def checkCudaErrors(result):
    if result[0].value:
        raise RuntimeError("CUDA error code={}({})".format(result[0].value, _cudaGetErrorEnum(result[0])))
    if len(result) == 1:
        return None
    elif len(result) == 2:
        return result[1]
    else:
        return result[1:]



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

        # compilation of cuda code into ptx for joint execution with python
        with open('model_signing/hashing/merkle_tree.cu', 'r') as f:
            code = f.read()

        driver.cuInit(0)
        cuDevice = checkCudaErrors(runtime.cudaGetDevice())
        major = checkCudaErrors(driver.cuDeviceGetAttribute(driver.CUdevice_attribute.CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR, cuDevice))
        minor = checkCudaErrors(driver.cuDeviceGetAttribute(driver.CUdevice_attribute.CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR, cuDevice))
        arch_arg = bytes(f'--gpu-architecture=compute_{major}{minor}', 'ascii')
        prog = checkCudaErrors(nvrtc.nvrtcCreateProgram(str.encode(code), b'merkle_tree.cuh', 0, [], []))
        opts = [b'--fmad=false', arch_arg]
        checkCudaErrors(nvrtc.nvrtcCompileProgram(prog, len(opts), opts))
        ptxSize = checkCudaErrors(nvrtc.nvrtcGetPTXSize(prog))
        ptx = b' ' * ptxSize
        checkCudaErrors(nvrtc.nvrtcGetPTX(prog, ptx))
        self.context = checkCudaErrors(driver.cuCtxCreate(0, cuDevice))
        self.stream = checkCudaErrors(runtime.cudaStreamCreate())
        ptx = np.char.array(ptx)
        module = checkCudaErrors(driver.cuModuleLoadData(ptx.ctypes.data))
        self.merkle_tree_pre = checkCudaErrors(driver.cuModuleGetFunction(module, b'merkle_tree_pre'))
        self.merkle_tree_hash = checkCudaErrors(driver.cuModuleGetFunction(module, b'merkle_tree_hash'))

    def __del__(self):
        # checkCudaErrors(runtime.cudaStreamDestroy(self.stream))
        # checkCudaErrors(driver.cuModuleUnload(self.merkle_tree_pre))
        # checkCudaErrors(driver.cuModuleUnload(self.merkle_tree_hash))
        # checkCudaErrors(driver.cuCtxDestroy(self.context))
        pass

    def set_state(self, state: collections.OrderedDict) -> None:
        """Redefines the state to be hashed in `compute`."""
        self._state = state

    @property
    @override
    def digest_name(self) -> str:
        if self._digest_name_override is not None:
            return self._digest_name_override
        return f"state-{self._content_hasher.digest_name}"
    
    def merkle_tree(self, content, blockSize) -> hashing.Digest:
        buffer = checkCudaErrors(runtime.cudaMalloc(nBytes))
        buffer = np.array([int(buffer)], dtype=np.uint64)

        content = np.array([int(content)], dtype=np.uint64)
        blockSize = np.array([int(blockSize)], dtype=np.uint64)

        nThread = (nBytes + (blockSize-1)) // blockSize
        nThread = np.array([int(nThread)], dtype=np.uint64)

        args = [buffer, content, blockSize, nThread]
        args = np.array([arg.ctypes.data for arg in args], dtype=np.uint64)

        block = min(1024, nThread)
        grid = (nThread + (block-1)) // block

        checkCudaErrors(driver.cuLaunchKernel(
            merkle_tree_pre, grid, 1, 1, block, 1, 1,
            0, self.stream, args.ctypes.data, 0,
        ))
        nThread //= 2

        while nThread > 0:
            args = [content, buffer, blockSize, nThread]
            args = np.array([arg.ctypes.data for arg in args], dtype=np.uint64)

            block = min(1024, nThread)
            grid = (nThread + (block-1)) // block

            checkCudaErrors(driver.cuLaunchKernel(
                merkle_tree_hash, grid, 1, 1, block, 1, 1,
                0, self.stream, args.ctypes.data, 0,
            ))

            checkCudaErrors(runtime.cudaMemcpy2D(buffer, DIGEST_SIZE, content,
                1024*blockSize, 1, grid, cudaMemcpyDeviceToDevice))
            nThread //= 2048

        checkCudaErrors(runtime.cudaMemcpy(digest, buffer, DIGEST_SIZE,
            cudaMemcpyDeviceToDevice))

    @override
    def compute(self) -> hashing.Digest:
        self._content_hasher.reset()

        for v in self._state.values():
            v = v.flatten()
            if not hasattr(self, '_buffer'):
                self._buffer = v
            else:
                self._buffer = torch.cat((self._buffer, v))

        # merkle_tree()

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
