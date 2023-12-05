import os
from pathlib import Path
import pytest
from serialize import Serializer
import shutil


testdata_dir = "testdata"


# Utility functions.
def create_empty_folder(name: str) -> Path:
    p = os.path.join(os.getcwd(), testdata_dir, name)
    os.makedirs(p)
    return Path(p)


def create_random_folders(name: str) -> (Path, int, [Path], [Path]):
    p = os.path.join(os.getcwd(), testdata_dir, name)

    content = os.urandom(1)
    dirs = [p]
    # Generate 8 directories.
    for i in range(8):
        bit = (content[0] >> i) & 1
        if bit > 0:
            # Add depth to the previously-created directory.
            dirs[-1] = os.path.join(dirs[-1], "dir_%d" % i)
        else:
            # Add a directory in the same directory as the previous entry.
            parent = os.path.dirname(dirs[-1])
            if Path(parent) == Path(p).parent:
                parent = str(p)
            dirs += [os.path.join(parent, "dir_%d" % i)]
    for d in dirs:
        os.makedirs(d)

    # Create at most 3 files in each directory.
    files = []
    for d in dirs:
        b = os.urandom(1)
        n = b[0] & 3
        for i in range(n):
            files += [os.path.join(d, "file_%d" % n)]
            content = os.urandom(28)
            with open(files[-1], "wb") as f:
                f.write(content)

    return Path(p), 28, [Path(d) for d in sorted(dirs)], [Path(f) for f in sorted(files)]  # noqa: E501 ignore long line warning


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
    # File serialization works.
    def test_known_file(self):
        file = "v0_test_known_file"
        data = b"hellow world content"
        model = create_file(file, data)
        sig_path = signature_path(model)
        expected = b'x\x9d\xa4N\x9f\xeajd\xd8\x87\x84\x1a\xd3\xb3\xfc\xeb\xf6\r\x01\x9fi8#\xd8qU\x90\xca\x9d\x83\xe1\x8b'  # noqa: E501 ignore long line warning
        computed = Serializer.serialize_v0(model, 0, sig_path)
        assert (computed == expected)
        cleanup_model(model)

    # File serialization returns the same results for different chunk sizes.
    def test_file_chunks(self):
        file = "v0_test_file_chunks"
        file_size = 999
        model, _ = create_random_file(file, file_size)
        sig_path = signature_path(model)
        result = Serializer.serialize_v0(model, 0, sig_path)
        # NOTE: we want to also test a chunk size larger than the files size.
        for c in range(1, file_size + 1):
            r = Serializer.serialize_v0(model, c, sig_path)
            assert (r == result)
        cleanup_model(model)

    # File serialization raises error for negative chunk values.
    def test_file_negative_chunks(self):
        file = "v0_test_file_negative_chunks"
        data = b"hellow world content"
        model = create_file(file, data)
        sig_path = signature_path(model)
        with pytest.raises(ValueError):
            _ = Serializer.serialize_v0(model, -1, sig_path)
        cleanup_model(model)

    # File serialization returns the same results for different file names.
    def test_different_filename(self):
        file = "v0_test_different_filename"
        data = b"hellow world content"
        model = create_file(file, data)
        sig_path = signature_path(model)
        r0 = Serializer.serialize_v0(model, 0, sig_path)
        cleanup_model(model)

        file = "v0_test_different_filename2"
        model = create_file(file, data)
        sig_path = signature_path(model)
        r1 = Serializer.serialize_v0(model, 0, sig_path)
        cleanup_model(model)

        assert (r0 == r1)

    # File serialization returns a different result for different model
    # contents.
    def test_altered_file(self):
        file = "v0_test_altered_file"
        file_size = 999
        model, content = create_random_file(file, file_size)
        sig_path = signature_path(model)
        result = Serializer.serialize_v0(model, 0, sig_path)
        for c in range(file_size):
            altered_content = content[:c] + bytes([content[c] ^ 1]) + \
                content[c+1:]
            altered_file = file + (".%d" % c)
            altered_model = create_file(altered_file, altered_content)
            altered_sig_path = signature_path(altered_model)
            altered_result = Serializer.serialize_v0(altered_model, 0,
                                                     altered_sig_path)
            assert (altered_result != result)
            cleanup_model(altered_model)
        cleanup_model(model)

    # symlink in root folder raises ValueError exception.
    def test_folder_symlink_root(self):
        folder = "v0_test_folder_symlink_root"
        model = create_empty_folder(folder)
        sig = signature_path(model)
        create_symlinks(".", os.path.join(folder, "root_link"))
        with pytest.raises(ValueError):
            Serializer.serialize_v0(Path(folder), 0, sig)
        cleanup_model(model)

    # symlink in non-root folder raises ValueError exception.
    def test_folder_symlink_nonroot(self):
        model = create_empty_folder("v0_test_folder_symlink_nonroot")
        sub_folder = model.joinpath("sub")
        create_empty_folder(str(sub_folder))
        sig = signature_path(model)
        create_symlinks(".", os.path.join(sub_folder, "sub_link"))
        with pytest.raises(ValueError):
            Serializer.serialize_v0(model, 0, sig)
        cleanup_model(model)

    # Folder serialization works.
    def test_known_folder(self):
        folder = "v0_test_known_folder"
        model = create_empty_folder(folder)
        sig = signature_path(model)
        os.mkdir(model.joinpath("dir1"))
        os.mkdir(model.joinpath("dir2"))
        os.mkdir(model.joinpath("dir3"))
        with open(model.joinpath("dir1", "f11"), "wb") as f:
            f.write(b"content f11")
        with open(model.joinpath("dir1", "f12"), "wb") as f:
            f.write(b"content f12")
        with open(model.joinpath("dir3", "f31"), "wb") as f:
            f.write(b"content f31")
        result = Serializer.serialize_v0(model, 0, sig)
        expected = b's\xac\xf7\xbdC\x14\x97fv\x97\x9c\xd3\xe4=,\xe7\x99.d(oP\xff\xe2\xd8~\xa2\x9cS\xe2/\xd9'  # noqa: E501 ignore long line warning
        assert (result == expected)
        cleanup_model(model)

    # Folder serialization raises error for negative chunk values.
    def test_folder_negative_chunks(self):
        dir = "v0_test_folder_negative_chunks"
        model = create_empty_folder(dir)
        sig_path = signature_path(model)
        with pytest.raises(ValueError):
            _ = Serializer.serialize_v0(model, -1, sig_path)
        cleanup_model(model)

    # Folder serialization returns the same results for different folder names.
    def test_different_dirname(self):
        folder = "v0_test_different_dirname"
        model = create_empty_folder(folder)
        sig = signature_path(model)
        os.mkdir(model.joinpath("dir1"))
        os.mkdir(model.joinpath("dir2"))
        os.mkdir(model.joinpath("dir3"))
        with open(model.joinpath("dir1", "f11"), "wb") as f:
            f.write(b"content f11")
        with open(model.joinpath("dir1", "f12"), "wb") as f:
            f.write(b"content f12")
        with open(model.joinpath("dir3", "f31"), "wb") as f:
            f.write(b"content f31")
        r0 = Serializer.serialize_v0(model, 0, sig)

        # Rename the folder.
        new_model = model.parent.joinpath("model_dir2")
        os.rename(model, new_model)
        sig_path = signature_path(new_model)
        r1 = Serializer.serialize_v0(new_model, 0, sig_path)
        cleanup_model(new_model)

        assert (r0 == r1)

    # Folder serialization returns the same results for different folder or
    # file names and / or file contents.
    def test_different_ignored_paths(self):
        folder = "v0_test_different_ignored_paths"
        model = create_empty_folder(folder)
        sig = signature_path(model)
        os.mkdir(model.joinpath("dir1"))
        os.mkdir(model.joinpath("dir2"))
        os.mkdir(model.joinpath("dir2/dir3"))
        with open(model.joinpath("dir1", "f11"), "wb") as f:
            f.write(b"content f11")
        with open(model.joinpath("dir2", "f21"), "wb") as f:
            f.write(b"content f21")
        with open(model.joinpath("dir2/dir3", "f31"), "wb") as f:
            f.write(b"content f31")
        r0 = Serializer.serialize_v1(model, 0, sig)
        r1 = Serializer.serialize_v0(model, 0, sig, [model.joinpath("dir1")])
        r2 = Serializer.serialize_v0(model, 0, sig, [model.joinpath("dir2")])
        r3 = Serializer.serialize_v0(model, 0, sig, [model.joinpath("dir2/dir3")])  # noqa: E501 ignore long line warning
        r4 = Serializer.serialize_v0(model, 0, sig, [model.joinpath("dir2/dir3/f31")])  # noqa: E501 ignore long line warning

        # Sanity checks.
        s = set({r0, r1, r2, r3, r4})
        assert (len(s) == 5)

        # Rename the file under dir1.
        new_file = model.joinpath("dir1/f11_altered")
        os.rename(model.joinpath("dir1/f11"), new_file)
        r11 = Serializer.serialize_v0(model, 0, sig, [model.joinpath("dir1")])
        assert (r11 == r1)
        os.rename(new_file, model.joinpath("dir1/f11"))

        # Update the file under dir1.
        r11 = Serializer.serialize_v0(model, 0, sig, [model.joinpath("dir1")])
        with open(model.joinpath("dir1", "f11"), "wb") as f:
            f.write(b"content f11 altered")
        assert (r11 == r1)
        with open(model.joinpath("dir1", "f11"), "wb") as f:
            f.write(b"content f11")

        # Rename the folder dir2.
        new_dir = model.joinpath("dir2/dir3_altered")
        os.rename(model.joinpath("dir2/dir3"), new_dir)
        r22 = Serializer.serialize_v0(model, 0, sig, [model.joinpath("dir2")])
        assert (r22 == r2)
        os.rename(new_dir, model.joinpath("dir2/dir3"))

        # Add a file under dir2.
        with open(model.joinpath("dir2", "new_file"), "wb") as f:
            f.write(b"new file!!")
        r22 = Serializer.serialize_v0(model, 0, sig, [model.joinpath("dir2")])
        assert (r22 == r2)
        os.unlink(model.joinpath("dir2", "new_file"))

        # Update the content of f31 file.
        with open(model.joinpath("dir2/dir3", "f31"), "wb") as f:
            f.write(b"content f31 altered")
        r22 = Serializer.serialize_v0(model, 0, sig, [model.joinpath("dir2")])
        assert (r22 == r2)
        r33 = Serializer.serialize_v0(model, 0, sig, [model.joinpath("dir2/dir3")])  # noqa: E501 ignore long line warning
        assert (r33 == r3)
        r44 = Serializer.serialize_v0(model, 0, sig, [model.joinpath("dir2/dir3/f31")])  # noqa: E501 ignore long line warning
        assert (r44 == r4)
        with open(model.joinpath("dir2/dir3", "f31"), "wb") as f:
            f.write(b"content f31")

        cleanup_model(model)

    # Folder serialization returns different results
    # for an empty file or directory with the same name.
    def test_file_dir(self):
        folder = "v0_test_file_dir"
        model = create_empty_folder(folder)
        sig = signature_path(model)
        os.mkdir(model.joinpath("dir1"))
        os.mkdir(model.joinpath("dir2"))
        os.mkdir(model.joinpath("dir3"))
        with open(model.joinpath("dir1", "f11"), "wb") as f:
            f.write(b"content f11")
        with open(model.joinpath("dir1", "f12"), "wb") as f:
            f.write(b"content f12")
        with open(model.joinpath("dir3", "f31"), "wb") as f:
            f.write(b"content f31")
        r0 = Serializer.serialize_v0(model, 0, sig)

        # Remove dir2 and create an empty file with the same name.
        dir2 = model.joinpath("dir2")
        os.rmdir(dir2)
        with open(dir2, 'w') as _:
            pass
        r1 = Serializer.serialize_v0(model, 0, sig)
        assert (r0 != r1)
        cleanup_model(model)

    # Folder serialization return different values for different
    # sub-directory names.
    def test_random_folder_different_folder_names(self):
        dir = "v0_test_random_folder_different_folder_names"
        model, _, dirs, _ = create_random_folders(dir)
        sig_path = signature_path(model)
        result = Serializer.serialize_v0(model, 0, sig_path)
        for d in dirs:
            if d == model:
                # Ignore the model folder.
                continue
            new_folder = d.parent.joinpath(d.name + "_altered")
            os.rename(d, new_folder)
            r = Serializer.serialize_v0(model, 0, sig_path)
            os.rename(new_folder, d)
            assert (r != result)
        cleanup_model(model)

    # Folder serialization return different values for different file names.
    def test_random_folder_different_filenames(self):
        dir = "v0_test_random_folder_different_filenames"
        model, _, _, files = create_random_folders(dir)
        sig_path = signature_path(model)
        result = Serializer.serialize_v0(model, 0, sig_path)
        for f in files:
            new_file = f.parent.joinpath(f.name + "_altered")
            os.rename(f, new_file)
            r = Serializer.serialize_v0(model, 0, sig_path)
            os.rename(new_file, f)
            assert (r != result)
        cleanup_model(model)

    # Folder serialization return different values for different file contents.
    def test_random_folder_different_file_content(self):
        dir = "v0_test_random_folder_different_file_content"
        model, _, _, files = create_random_folders(dir)
        sig_path = signature_path(model)
        result = Serializer.serialize_v0(model, 0, sig_path)
        for f in files:
            content = b''
            with open(f, "rb") as ff:
                content = ff.read()
            for c in range(len(content)):
                # Alter the file content, one byte at a time.
                altered_content = content[:c] + bytes([content[c] ^ 1]) + \
                    content[c+1:]
                with open(f, "wb") as ff:
                    ff.write(altered_content)
                r = Serializer.serialize_v0(model, 0, sig_path)
                assert (r != result)
            # Write the original content back to the file.
            with open(f, "wb") as ff:
                ff.write(content)
        cleanup_model(model)

    # Folder serialization return same results for different chunk sizes.
    def test_random_folder_different_chunks(self):
        dir = "v0_test_random_folder_different_chunks"
        model, max_size, _, _ = create_random_folders(dir)
        sig_path = signature_path(model)
        result = Serializer.serialize_v0(model, 0, sig_path)
        # NOTE: we want to also test a chunk size larger than the files size.
        for c in range(1, max_size + 1):
            r = Serializer.serialize_v0(model, c, sig_path)
            assert (r == result)
        cleanup_model(model)

    # Folder serialization raises an exception if the signature
    # file is not in the root folder.
    def test_folfer_invalid_sign_path(self):
        dir = "v0_test_folfer_invalid_sign_path"
        model = create_empty_folder(dir)
        sig_path = model.joinpath("sub/model.sig")
        with pytest.raises(ValueError):
            _ = Serializer.serialize_v0(model, 0, sig_path)
        cleanup_model(model)


class Test_serialize_v1:
    # File serialization works.
    def test_known_file(self):
        file = "v1_test_known_file"
        data = b"hellow world content"
        model = create_file(file, data)
        sig_path = signature_path(model)
        expected = b'\xfd\xe0s^{ \xf8\xed\xb4\x9c\xbf\xc0\xf6\x87\x0f\x1a\x896~\xeeBH\xec\xf57<\x9d\x04B"7\xb1'  # noqa: E501 ignore long line warning
        computed = Serializer.serialize_v1(model, 0, sig_path)
        assert (computed == expected)
        cleanup_model(model)

    # File serialization returns the same results for different chunk sizes.
    def test_file_chunks(self):
        file = "v1_test_file_chunks"
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
        file = "v1_test_file_negative_shards"
        data = b"hellow world content"
        model = create_file(file, data)
        sig_path = signature_path(model)
        with pytest.raises(ValueError):
            _ = Serializer._serialize_v1(model, 0, -1, sig_path)
        cleanup_model(model)

    # File serialization returns different results for different shard sizes.
    def test_file_shards(self):
        file = "v1_test_file_shards"
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
        file = "v1_test_file_shard_chunks"
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
        file = "v1_test_different_filename"
        data = b"hellow world content"
        model = create_file(file, data)
        sig_path = signature_path(model)
        r0 = Serializer.serialize_v1(model, 0, sig_path)
        cleanup_model(model)

        file = "v1_test_different_filename2"
        model = create_file(file, data)
        sig_path = signature_path(model)
        r1 = Serializer.serialize_v1(model, 0, sig_path)
        cleanup_model(model)

        assert (r0 == r1)

    # File serialization returns a different result for different model
    # contents.
    def test_altered_file(self):
        file = "v1_test_altered_file"
        file_size = 99
        model, content = create_random_file(file, file_size)
        sig_path = signature_path(model)
        result = Serializer._serialize_v1(model, 0, 19, sig_path)
        for c in range(file_size):
            altered_content = content[:c] + bytes([content[c] ^ 1]) + \
                content[c+1:]
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
        file = "v1_test_large_file"
        file_size = 1000100001
        model, _ = create_random_file(file, file_size)
        sig_path = signature_path(model)
        _ = Serializer.serialize_v1(model, 0, sig_path)
        cleanup_model(model)

    # symlink in root folder raises ValueError exception.
    def test_folder_symlink_root(self):
        folder = "v1_test_folder_symlink_root"
        model = create_empty_folder(folder)
        sig = signature_path(model)
        create_symlinks(".", os.path.join(folder, "root_link"))
        with pytest.raises(ValueError):
            Serializer.serialize_v1(Path(folder), 0, sig)
        cleanup_model(model)

    # symlink in non-root folder raises ValueError exception.
    def test_folder_symlink_nonroot(self):
        model = create_empty_folder("v1_test_folder_symlink_nonroot")
        sub_folder = model.joinpath("sub")
        create_empty_folder(str(sub_folder))
        sig = signature_path(model)
        create_symlinks(".", os.path.join(sub_folder, "sub_link"))
        with pytest.raises(ValueError):
            Serializer.serialize_v1(model, 0, sig)
        cleanup_model(model)

    # Folder serialization works.
    def test_known_folder(self):
        folder = "v1_test_known_folder"
        model = create_empty_folder(folder)
        sig = signature_path(model)
        os.mkdir(model.joinpath("dir1"))
        os.mkdir(model.joinpath("dir2"))
        os.mkdir(model.joinpath("dir3"))
        with open(model.joinpath("dir1", "f11"), "wb") as f:
            f.write(b"content f11")
        with open(model.joinpath("dir1", "f12"), "wb") as f:
            f.write(b"content f12")
        with open(model.joinpath("dir3", "f31"), "wb") as f:
            f.write(b"content f31")
        result = Serializer.serialize_v1(model, 0, sig)
        expected = b'\x8b\xc3\xdc\xf1\xaf\xd8\x1b\x1f\xa0\x18&\x0eo|\xc4\xc6f~]]\xd6\x91\x15\x94-Vm\xf6\xa5\xed\xc8L'  # noqa: E501 ignore long line warning
        assert (result == expected)
        cleanup_model(model)

    # Folder serialization raises error for negative chunk values.
    def test_folder_negative_chunks(self):
        dir = "v1_test_folder_negative_chunks"
        model = create_empty_folder(dir)
        sig_path = signature_path(model)
        with pytest.raises(ValueError):
            _ = Serializer.serialize_v1(model, -1, sig_path)
        cleanup_model(model)

    # Folder serialization returns the same results for different folder names.
    def test_different_dirname(self):
        folder = "v1_test_different_dirname"
        model = create_empty_folder(folder)
        sig = signature_path(model)
        os.mkdir(model.joinpath("dir1"))
        os.mkdir(model.joinpath("dir2"))
        os.mkdir(model.joinpath("dir3"))
        with open(model.joinpath("dir1", "f11"), "wb") as f:
            f.write(b"content f11")
        with open(model.joinpath("dir1", "f12"), "wb") as f:
            f.write(b"content f12")
        with open(model.joinpath("dir3", "f31"), "wb") as f:
            f.write(b"content f31")
        r0 = Serializer.serialize_v1(model, 0, sig)

        # Rename the folder.
        new_model = model.parent.joinpath("model_dir2")
        os.rename(model, new_model)
        sig_path = signature_path(new_model)
        r1 = Serializer.serialize_v1(new_model, 0, sig_path)
        cleanup_model(new_model)

        assert (r0 == r1)

    # Folder serialization returns the same results for different folder or
    # file names and / or file contents.
    def test_different_ignored_paths(self):
        folder = "v1_test_different_ignored_paths"
        model = create_empty_folder(folder)
        sig = signature_path(model)
        os.mkdir(model.joinpath("dir1"))
        os.mkdir(model.joinpath("dir2"))
        os.mkdir(model.joinpath("dir2/dir3"))
        with open(model.joinpath("dir1", "f11"), "wb") as f:
            f.write(b"content f11")
        with open(model.joinpath("dir2", "f21"), "wb") as f:
            f.write(b"content f21")
        with open(model.joinpath("dir2/dir3", "f31"), "wb") as f:
            f.write(b"content f31")
        r0 = Serializer.serialize_v1(model, 0, sig)
        r1 = Serializer.serialize_v1(model, 0, sig, [model.joinpath("dir1")])
        r2 = Serializer.serialize_v1(model, 0, sig, [model.joinpath("dir2")])
        r3 = Serializer.serialize_v1(model, 0, sig, [model.joinpath("dir2/dir3")])  # noqa: E501 ignore long line warning
        r4 = Serializer.serialize_v1(model, 0, sig, [model.joinpath("dir2/dir3/f31")])  # noqa: E501 ignore long line warning

        # Sanity checks.
        s = set({r0, r1, r2, r3, r4})
        assert (len(s) == 5)

        # Rename the file under dir1.
        new_file = model.joinpath("dir1/f11_altered")
        os.rename(model.joinpath("dir1/f11"), new_file)
        r11 = Serializer.serialize_v1(model, 0, sig, [model.joinpath("dir1")])
        assert (r11 == r1)
        os.rename(new_file, model.joinpath("dir1/f11"))

        # Update the file under dir1.
        r11 = Serializer.serialize_v1(model, 0, sig, [model.joinpath("dir1")])
        with open(model.joinpath("dir1", "f11"), "wb") as f:
            f.write(b"content f11 altered")
        assert (r11 == r1)
        with open(model.joinpath("dir1", "f11"), "wb") as f:
            f.write(b"content f11")

        # Rename the folder dir2.
        new_dir = model.joinpath("dir2/dir3_altered")
        os.rename(model.joinpath("dir2/dir3"), new_dir)
        r22 = Serializer.serialize_v1(model, 0, sig, [model.joinpath("dir2")])
        assert (r22 == r2)
        os.rename(new_dir, model.joinpath("dir2/dir3"))

        # Add a file under dir2.
        with open(model.joinpath("dir2", "new_file"), "wb") as f:
            f.write(b"new file!!")
        r22 = Serializer.serialize_v1(model, 0, sig, [model.joinpath("dir2")])
        assert (r22 == r2)
        os.unlink(model.joinpath("dir2", "new_file"))

        # Update the content of f31 file.
        with open(model.joinpath("dir2/dir3", "f31"), "wb") as f:
            f.write(b"content f31 altered")
        r22 = Serializer.serialize_v1(model, 0, sig, [model.joinpath("dir2")])
        assert (r22 == r2)
        r33 = Serializer.serialize_v1(model, 0, sig, [model.joinpath("dir2/dir3")])  # noqa: E501 ignore long line warning
        assert (r33 == r3)
        r44 = Serializer.serialize_v1(model, 0, sig, [model.joinpath("dir2/dir3/f31")])  # noqa: E501 ignore long line warning
        assert (r44 == r4)
        with open(model.joinpath("dir2/dir3", "f31"), "wb") as f:
            f.write(b"content f31")

        cleanup_model(model)

    # Folder serialization returns different results
    # for an empty file or directory with the same name.
    def test_file_dir(self):
        folder = "v1_test_file_dir"
        model = create_empty_folder(folder)
        sig = signature_path(model)
        os.mkdir(model.joinpath("dir1"))
        os.mkdir(model.joinpath("dir2"))
        os.mkdir(model.joinpath("dir3"))
        with open(model.joinpath("dir1", "f11"), "wb") as f:
            f.write(b"content f11")
        with open(model.joinpath("dir1", "f12"), "wb") as f:
            f.write(b"content f12")
        with open(model.joinpath("dir3", "f31"), "wb") as f:
            f.write(b"content f31")
        r0 = Serializer.serialize_v1(model, 0, sig)

        # Remove dir2 and create an empty file with the same name.
        dir2 = model.joinpath("dir2")
        os.rmdir(dir2)
        with open(dir2, 'w') as _:
            pass
        r1 = Serializer.serialize_v1(model, 0, sig)
        assert (r0 != r1)
        cleanup_model(model)

    # Folder serialization return different values for different
    # sub-directory names.
    def test_random_folder_different_folder_names(self):
        dir = "v1_test_random_folder_different_folder_names"
        model, _, dirs, _ = create_random_folders(dir)
        sig_path = signature_path(model)
        result = Serializer.serialize_v1(model, 0, sig_path)
        for d in dirs:
            if d == model:
                # Ignore the model folder.
                continue
            new_folder = d.parent.joinpath(d.name + "_altered")
            os.rename(d, new_folder)
            r = Serializer.serialize_v1(model, 0, sig_path)
            os.rename(new_folder, d)
            assert (r != result)
        cleanup_model(model)

    # Folder serialization return different values for different file names.
    def test_random_folder_different_filenames(self):
        dir = "v1_test_random_folder_different_filenames"
        model, _, _, files = create_random_folders(dir)
        sig_path = signature_path(model)
        result = Serializer.serialize_v1(model, 0, sig_path)
        for f in files:
            new_file = f.parent.joinpath(f.name + "_altered")
            os.rename(f, new_file)
            r = Serializer.serialize_v1(model, 0, sig_path)
            os.rename(new_file, f)
            assert (r != result)
        cleanup_model(model)

    # Folder serialization return different values for different file contents.
    def test_random_folder_different_file_content(self):
        dir = "v1_test_random_folder_different_file_content"
        model, _, _, files = create_random_folders(dir)
        sig_path = signature_path(model)
        result = Serializer.serialize_v1(model, 0, sig_path)
        for f in files:
            content = b''
            with open(f, "rb") as ff:
                content = ff.read()
            for c in range(len(content)):
                # Alter the file content, one byte at a time.
                altered_content = content[:c] + bytes([content[c] ^ 1]) + \
                    content[c+1:]
                with open(f, "wb") as ff:
                    ff.write(altered_content)
                r = Serializer.serialize_v1(model, 0, sig_path)
                assert (r != result)
            # Write the original content back to the file.
            with open(f, "wb") as ff:
                ff.write(content)
        cleanup_model(model)

    # Folder serialization return same results for different chunk sizes.
    def test_random_folder_different_chunks(self):
        dir = "v1_test_random_folder_different_chunks"
        model, max_size, _, _ = create_random_folders(dir)
        sig_path = signature_path(model)
        result = Serializer.serialize_v1(model, 0, sig_path)
        # NOTE: we want to also test a chunk size larger than the files size.
        for c in range(1, max_size + 1):
            r = Serializer.serialize_v1(model, c, sig_path)
            assert (r == result)
        cleanup_model(model)

    # Folder serialization raises an exception if the signature
    # file is not in the root folder.
    def test_folfer_invalid_sign_path(self):
        dir = "v1_test_folfer_invalid_sign_path"
        model = create_empty_folder(dir)
        sig_path = model.joinpath("sub/model.sig")
        with pytest.raises(ValueError):
            _ = Serializer.serialize_v1(model, 0, sig_path)
        cleanup_model(model)

    # Folder serialization raises an exception for negative shard sizes.
    def test_folder_negative_shards(self):
        folder = "v1_test_folder_negative_shards"
        model = create_empty_folder(folder)
        sig_path = signature_path(model)
        with pytest.raises(ValueError):
            _ = Serializer._serialize_v1(model, 0, -1, sig_path)
        cleanup_model(model)

    # Folder serialization returns different results for different shard sizes.
    def test_folder_shards(self):
        dir = "v1_test_folder_shards"
        model, max_size, _, files = create_random_folders(dir)
        sig_path = signature_path(model)
        result = Serializer._serialize_v1(model, 1, 1, sig_path)
        results = [result]
        for shard in range(2, max_size + 1):
            r = Serializer._serialize_v1(model, 1, shard, sig_path)
            assert (r not in results)
            results += [r]
        cleanup_model(model)

    # Folder serialization returns different results for different shard sizes
    # but same results for different chunk sizes with shard size fixed.
    def test_folder_shard_chunks(self):
        dir = "v1_test_folder_shard_chunks"
        model, max_size, _, _ = create_random_folders(dir)
        sig_path = signature_path(model)
        result = Serializer._serialize_v1(model, 1, 1, sig_path)
        results = [result]
        for shard in range(2, max_size + 1):
            r = Serializer._serialize_v1(model, 1, shard, sig_path)
            assert (r not in results)
            results += [r]
            for c in range(1, max_size + 1):
                rc = Serializer._serialize_v1(model, c, shard, sig_path)
                assert (rc == r)
        cleanup_model(model)
