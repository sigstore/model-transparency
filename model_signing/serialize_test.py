import os
from pathlib import Path
import pytest
from serialize import Serializer
import shutil


testdata_dir = "testdata"


# Utility functions.
def create_folder(name: str) -> Path:
    p = os.path.join(os.getcwd(), testdata_dir, name)
    os.makedirs(p)
    return Path(p)


def create_symlinks(src: str, dst: str) -> Path:
    psrc = os.path.join(os.getcwd(), testdata_dir, src)
    pdst = os.path.join(os.getcwd(), testdata_dir, dst)
    os.symlink(psrc, pdst)
    return Path(dst)


def cleanup_model(p: Path) -> None:
    if p.is_dir():
        shutil.rmtree(p)
    elif p.is_file():
        os.unlink(p)
        try:
            os.unlink(p.with_suffix(".sig"))
        except FileNotFoundError:
            pass


def create_file(name: str, data: bytes) -> Path:
    p = os.path.join(os.getcwd(), testdata_dir, name)
    with open(p, "wb") as f:
        f.write(data)
    return Path(p)


def create_random_file(name: str, size: int) -> (Path, bytes):
    p = os.path.join(os.getcwd(), testdata_dir, name)
    content = os.urandom(size)
    with open(p, "wb") as f:
        f.write(content)
    return Path(p), content


def signature_path(model: Path) -> Path:
    if model.is_file():
        return model.with_suffix(".sig")
    return model.joinpath("model.sig")


class Test_serialize_v0:
    # symlink in root folder raises ValueError exception.
    def test_symlink_root(self):
        folder = "with_root_symlinks"
        model = create_folder(folder)
        sig = signature_path(model)
        create_symlinks(".", os.path.join(folder, "root_link"))
        with pytest.raises(ValueError):
            Serializer.serialize_v0(Path(folder), 0, sig)
        cleanup_model(model)

    # symlink in non-root folder raises ValueError exception.
    def test_symlink_nonroot(self):
        model = create_folder("with_nonroot_symlinks")
        sub_folder = model.joinpath("sub")
        create_folder(str(sub_folder))
        sig = signature_path(model)
        create_symlinks(".", os.path.join(sub_folder, "sub_link"))
        with pytest.raises(ValueError):
            Serializer.serialize_v0(model, 0, sig)
        cleanup_model(model)

    # File serialization works.
    def test_known_file(self):
        file = "model_file"
        data = b"hellow world content"
        model = create_file(file, data)
        sig_path = signature_path(model)
        expected = b'x\x9d\xa4N\x9f\xeajd\xd8\x87\x84\x1a\xd3\xb3\xfc\xeb\xf6\r\x01\x9fi8#\xd8qU\x90\xca\x9d\x83\xe1\x8b'  # noqa: E501 ignore long line warning
        computed = Serializer.serialize_v0(model, 0, sig_path)
        assert (computed == expected)
        cleanup_model(model)

    # File serialization returns the same results for different chunk sizes.
    def test_file_chuncks(self):
        file = "model_file"
        file_size = 999
        model, _ = create_random_file(file, file_size)
        sig_path = signature_path(model)
        result = Serializer.serialize_v0(model, 0, sig_path)
        results = [result]
        # NOTE: we want to also test a chunk size larger than the files size.
        for c in range(1, file_size + 1):
            r = Serializer.serialize_v0(model, c, sig_path)
            assert (r not in results)
            results += [r]
        cleanup_model(model)

    # File serialization raises error for negativ chunk values.
    def test_file_negative_chuncks(self):
        file = "model_file"
        data = b"hellow world content"
        model = create_file(file, data)
        sig_path = signature_path(model)
        with pytest.raises(ValueError):
            _ = Serializer.serialize_v0(model, -1, sig_path)
        cleanup_model(model)

    # File serialization returns the same results for different file names.
    def test_different_filename(self):
        file = "model_file"
        data = b"hellow world content"
        model = create_file(file, data)
        sig_path = signature_path(model)
        r0 = Serializer.serialize_v0(model, 0, sig_path)
        cleanup_model(model)

        file = "model_file2"
        model = create_file(file, data)
        sig_path = signature_path(model)
        r1 = Serializer.serialize_v0(model, 0, sig_path)
        cleanup_model(model)

        assert (r0 == r1)

    # File serialization returns a different result for different model
    # contents.
    def test_altered_file(self):
        file = "model_file"
        file_size = 999
        model, content = create_random_file(file, file_size)
        sig_path = signature_path(model)
        result = Serializer.serialize_v0(model, 0, sig_path)
        for c in range(file_size):
            altered_content = content[:c] + bytes([content[c] | 1]) + \
                content[c:]
            altered_file = file + (".%d" % c)
            altered_model = create_file(altered_file, altered_content)
            altered_sig_path = signature_path(altered_model)
            altered_result = Serializer.serialize_v0(altered_model, 0,
                                                     altered_sig_path)
            assert (altered_result != result)
            cleanup_model(altered_model)
        cleanup_model(model)

    # TODO(#57): directory support.


class Test_serialize_v1:
    # symlink in root folder raises ValueError exception.
    def test_symlink_root(self):
        folder = "with_root_symlinks"
        model = create_folder(folder)
        sig = signature_path(model)
        create_symlinks(".", os.path.join(folder, "root_link"))
        with pytest.raises(ValueError):
            Serializer.serialize_v1(Path(folder), 0, sig)
        cleanup_model(model)

    # symlink in non-root folder raises ValueError exception.
    def test_symlink_nonroot(self):
        model = create_folder("with_nonroot_symlinks")
        sub_folder = model.joinpath("sub")
        create_folder(str(sub_folder))
        sig = signature_path(model)
        create_symlinks(".", os.path.join(sub_folder, "sub_link"))
        with pytest.raises(ValueError):
            Serializer.serialize_v1(model, 0, sig)
        cleanup_model(model)

    # File serialization works.
    def test_known_file(self):
        file = "model_file"
        data = b"hellow world content"
        model = create_file(file, data)
        sig_path = signature_path(model)
        expected = b'\xfd\xe0s^{ \xf8\xed\xb4\x9c\xbf\xc0\xf6\x87\x0f\x1a\x896~\xeeBH\xec\xf57<\x9d\x04B"7\xb1'  # noqa: E501 ignore long line warning
        computed = Serializer.serialize_v1(model, 0, sig_path)
        assert (computed == expected)
        cleanup_model(model)

    # File serialization returns the same results for different chunk sizes.
    def test_file_chuncks(self):
        file = "model_file"
        file_size = 99
        model, _ = create_random_file(file, file_size)
        sig_path = signature_path(model)
        result = Serializer.serialize_v1(model, 0, sig_path)
        # NOTE: we want to also test a chunk size larger than the files size.
        for c in range(1, file_size + 1):
            r = Serializer.serialize_v1(model, c, sig_path)
            assert (r == result)
        cleanup_model(model)

    # File serialization raises an exception for negative shard sizes.
    def test_file_negative_shards(self):
        file = "model_file"
        data = b"hellow world content"
        model = create_file(file, data)
        sig_path = signature_path(model)
        with pytest.raises(ValueError):
            _ = Serializer._serialize_v1(model, 0, -1, sig_path)
        cleanup_model(model)

    # File serialization returns different results for different shard sizes.
    def test_file_shards(self):
        file = "model_file"
        file_size = 99
        model, _ = create_random_file(file, file_size)
        sig_path = signature_path(model)
        result = Serializer._serialize_v1(model, 1, 1, sig_path)
        results = [result]
        for shard in range(2, file_size + 1):
            r = Serializer._serialize_v1(model, 1, shard, sig_path)
            assert (r not in results)
            results += [r]
        cleanup_model(model)

    # File serialization returns different results for different shard sizes
    # but same results for different chunk sizes with shard size fixed.
    def test_file_shard_chunks(self):
        file = "model_file"
        file_size = 21
        model, _ = create_random_file(file, file_size)
        sig_path = signature_path(model)
        result = Serializer._serialize_v1(model, 1, 1, sig_path)
        results = [result]
        for shard in range(2, file_size + 1):
            r = Serializer._serialize_v1(model, 1, shard, sig_path)
            assert (r not in results)
            results += [r]
            for c in range(1, file_size + 1):
                rc = Serializer._serialize_v1(model, c, shard, sig_path)
                assert (rc == r)
        cleanup_model(model)

    # File serialization returns the same results for different file names.
    def test_different_filename(self):
        file = "model_file"
        data = b"hellow world content"
        model = create_file(file, data)
        sig_path = signature_path(model)
        r0 = Serializer.serialize_v1(model, 0, sig_path)
        cleanup_model(model)

        file = "model_file2"
        model = create_file(file, data)
        sig_path = signature_path(model)
        r1 = Serializer.serialize_v1(model, 0, sig_path)
        cleanup_model(model)

        assert (r0 == r1)

    # File serialization returns a different result for different model
    # contents.
    def test_altered_file(self):
        file = "model_file"
        file_size = 999
        model, content = create_random_file(file, file_size)
        sig_path = signature_path(model)
        result = Serializer._serialize_v1(model, 0, 19, sig_path)
        for c in range(file_size):
            altered_content = content[:c] + bytes([content[c] | 1]) + \
                content[c:]
            altered_file = file + (".%d" % c)
            altered_model = create_file(altered_file, altered_content)
            altered_sig_path = signature_path(altered_model)
            altered_result = Serializer._serialize_v1(altered_model, 0,
                                                      19, altered_sig_path)
            assert (altered_result != result)
            cleanup_model(altered_model)
        cleanup_model(model)

    # File serialization works on large files.
    def test_large_file(self):
        file = "model_file"
        file_size = 1000100001
        model, _ = create_random_file(file, file_size)
        sig_path = signature_path(model)
        _ = Serializer.serialize_v1(model, 0, sig_path)
        cleanup_model(model)

    # TODO(#57): directory support.
