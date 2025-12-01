# Copyright (c) 2025, IBM CORPORATION.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import pathlib
import shutil
import subprocess
import sys

import pytest

import model_signing
from model_signing._signing.pkcs11uri import Pkcs11URI
from model_signing._signing.pkcs11uri import escape


MODULE_PATHS = [
    "/usr/lib64/pkcs11/",  # Fedora, RHEL, openSUSE
    "/usr/lib/pkcs11/",  # Fedora 32 bit, ArchLinux
    "/usr/lib/softhsm/",  # Ubuntu, Debian, Alpine
]


class TestPkcs11URI:
    def verify_uri(self, uri: Pkcs11URI, expecteduri: str) -> None:
        encoded = uri.format()
        assert encoded == expecteduri

    def verify_pin(self, uri: Pkcs11URI, expectedpin: str) -> None:
        assert uri.has_pin()
        pin = uri.get_pin()
        assert pin == expectedpin

    def _test_construct(self, uri: Pkcs11URI, expecteduri: str) -> None:
        self.verify_uri(uri, expecteduri)

        expectedpin = "the pin"
        expecteduri += "?pin-value=the%20pin"

        uri.add_query_attribute("pin-value", "the%20pin")

        self.verify_uri(uri, expecteduri)
        self.verify_pin(uri, expectedpin)

        uri.remove_query_attribute("pin-value")
        uri.add_query_attribute_unencoded(
            "pin-value", expectedpin.encode("utf-8")
        )

        self.verify_uri(uri, expecteduri)
        self.verify_pin(uri, expectedpin)

    def test_construct1(self) -> None:
        uri = Pkcs11URI()

        uri.add_path_attribute("id", "%66oo")
        self._test_construct(uri, "pkcs11:id=%66%6F%6F")

    def test_construct2(self) -> None:
        uri = Pkcs11URI()

        uri.add_path_attribute_unencoded("id", b"\x66\x6f\x6f")
        self._test_construct(uri, "pkcs11:id=%66%6F%6F")

    def test_construct3(self) -> None:
        uri = Pkcs11URI()

        uri.add_path_attribute("slot-id", "12345")
        self._test_construct(uri, "pkcs11:slot-id=12345")

    def test_construct4(self) -> None:
        uri = Pkcs11URI()

        uri.add_path_attribute_unencoded("slot-id", b"12345")
        self._test_construct(uri, "pkcs11:slot-id=12345")

    def test_pin_source(self, tmp_path: pathlib.Path) -> None:
        uri = Pkcs11URI()

        expectedpin = "4321"

        tmpfile = tmp_path.joinpath("pinfile")
        tmpfile.write_bytes(expectedpin.encode("utf-8"))

        # Need to escape paths for Windows
        expecteduri = "pkcs11:id=%66%6F%6F?pin-source=file:" + escape(
            str(tmpfile), False
        )
        uri.add_path_attribute("id", "foo")
        uri.add_query_attribute("pin-source", "file:" + str(tmpfile), True)

        self.verify_uri(uri, expecteduri)
        self.verify_pin(uri, expectedpin)

        if sys.platform in ["Linux", "darwin"]:
            expecteduri = "pkcs11:id=%66%6F%6F?pin-source=" + escape(
                str(tmpfile), False
            )
            uri.remove_query_attribute("pin-source")
            uri.add_query_attribute("pin-source", str(tmpfile), True)

            self.verify_uri(uri, expecteduri)
            self.verify_pin(uri, expectedpin)

    def test_bad_input(self) -> None:
        uri = Pkcs11URI()

        for entry in [
            ("slot-id", "foo", "slot-id must be a number"),
            (
                "library-version",
                "foo",
                "Invalid format for library-version 'foo'",
            ),
            (
                "library-version",
                "1.bar",
                "Invalid format for library-version '1.bar'",
            ),
            ("type", "foobar", "Invalid type 'foobar'"),
        ]:
            uri.add_path_attribute(entry[0], entry[1])
            with pytest.raises(ValueError, match=entry[2]):
                uri.validate()
            uri.remove_path_attribute(entry[0])

    def test_good_input(self) -> None:
        uri = Pkcs11URI()

        for entry in [
            ("slot-id", "1"),
            ("library-version", "7"),
            ("library-version", "1.8"),
            ("type", "public"),
        ]:
            uri.add_path_attribute(entry[0], entry[1])
            uri.validate()
            uri.remove_path_attribute(entry[0])

    def test_uris(self) -> None:
        uri = Pkcs11URI()

        for uristring in [
            "pkcs11:",
            "pkcs11:object=my-pubkey;type=public",
            "pkcs11:object=my-key;type=private?pin-source=file:/etc/token",
            "pkcs11:token=The%20Software%20PKCS%2311%20Softtoken;manufacturer=Snake%20Oil,%20Inc.;model=1.0;object=my-certificate;type=cert;id=%69%95%3E%5C%F4%BD%EC%91;serial=?pin-source=file:/etc/token_pin",
            "pkcs11:object=my-sign-key;type=private?module-name=mypkcs11",
            "pkcs11:object=my-sign-key;type=private?module-path=/mnt/libmypkcs11.so.1",
            "pkcs11:token=Software%20PKCS%2311%20softtoken;manufacturer=Snake%20Oil,%20Inc.?pin-value=the-pin",
            "pkcs11:slot-description=Sun%20Metaslot",
            "pkcs11:library-manufacturer=Snake%20Oil,%20Inc.;library-description=Soft%20Token%20Library;library-version=1.23",
            "pkcs11:token=My%20token%25%20created%20by%20Joe;library-version=3;id=%01%02%03%Ba%dd%Ca%fe%04%05%06",
            "pkcs11:token=A%20name%20with%20a%20substring%20%25%3B;object=my-certificate;type=cert",
            "pkcs11:token=Name%20with%20a%20small%20A%20with%20acute:%20%C3%A1;object=my-certificate;type=cert",
            "pkcs11:token=my-token;object=my-certificate;type=cert;vendor-aaa=value-a?pin-source=file:/etc/token_pin&vendor-bbb=value-b",
        ]:
            # Skip test with an absolute module-path that is not accepted on
            # Windows
            if uristring.find("module-path=/") >= 0 and sys.platform not in [
                "linux",
                "darwin",
            ]:
                continue
            uri.parse(uristring)
            encoded = uri.format()
            assert len(encoded) == len(uristring)

    def test_validate_escaped_attrs(self) -> None:
        uri = Pkcs11URI()

        for input in [
            {
                "uri": "pkcs11:token=Software%20PKCS%2311%20softtoken;manufacturer=Snake%20Oil,%20Inc.?pin-value=the-pin",  # noqa
                "testp": [
                    "token",
                    "Software PKCS#11 softtoken",
                    "Software%20PKCS%2311%20softtoken",
                ],
                "format": False,
            },
            {
                "uri": "pkcs11:token=My%20token%25%20created%20by%20Joe;library-version=3;id=%01%02%03%Ba%dd%Ca%fe%04%05%06",  # noqa
                "testp": [
                    "token",
                    "My token% created by Joe",
                    "My%20token%25%20created%20by%20Joe",
                ],
                "format": False,
            },
            {
                # test pk11-query-res-avail and pk11-path-res-avail special
                # characters
                "uri": "pkcs11:token=:[]@!$'()*+,=&?attr=:[]@!$'()*+,=/?",
                "testp": ["token", ":[]@!$'()*+,=&", ":[]@!$'()*+,=&"],
                "testq": ["attr", ":[]@!$'()*+,=/?", ":[]@!$'()*+,=/?"],
                "format": True,
            },
            {
                # test (some) unnecessarily escaped characters
                "uri": "pkcs11:token=%3a%5b%5d%40%21%24%27%28%29%2a%2b%2c%26%3d-%60%20%3c%3e%7b",  # noqa
                "testp": [
                    "token",
                    ":[]@!$'()*+,&=-` <>{",
                    ":[]@!$'()*+,&=-%60%20%3C%3E%7B",
                ],
                "format": False,
            },
            {
                # test some non-printable characters that have to be escape;
                "uri": "pkcs11:token=%00%01%02Hello%FF%FE",
                "testp": [
                    "token",
                    "\x00\x01\x02Hello\xff\xfe",
                    "%00%01%02Hello%FF%FE",
                ],
                "format": True,
            },
        ]:
            uri.parse(input["uri"])
            v = uri.get_path_attribute(input["testp"][0], False)
            assert v == input["testp"][1]
            v = uri.get_path_attribute(input["testp"][0], True)
            assert v == input["testp"][2]

            if input.get("testq"):
                v = uri.get_query_attribute(input["testq"][0], False)
                assert v == input["testq"][1]
                v = uri.get_query_attribute(input["testq"][0], True)
                assert v == input["testq"][2]

            if input["format"]:
                assert input["uri"] == uri.format()

    def test_get_module(self) -> None:
        uri = Pkcs11URI()
        uri.set_module_directories(MODULE_PATHS)
        uri.set_allow_any_module(True)

        uristring = "pkcs11:?module-name=softhsm2"
        uri.parse(uristring)
        if shutil.which("softhsm2-util") is not None:
            uri.get_module()

    def test_get_module_restricted(self) -> None:
        uri = Pkcs11URI()
        uri.set_module_directories(MODULE_PATHS)
        uri.set_allow_any_module(False)

        uristring = "pkcs11:?module-name=softhsm2"
        uri.parse(uristring)

        if shutil.which("softhsm2-util") is not None:
            uri.set_allowed_module_paths(["/usr"])
            with pytest.raises(ValueError, match=".*is not allowed by policy$"):
                uri.get_module()

            uri.set_allowed_module_paths(MODULE_PATHS)
            uri.get_module()


class TestPkcs11SoftHSMSigning:
    def run_softhsm_setup(self, cmd: str) -> tuple[bytes | None, int]:
        curr_dir = os.path.dirname(os.path.realpath(__file__))
        softhsm_setup = os.path.join(
            curr_dir, "../../scripts/pkcs11-tests/softhsm_setup"
        )
        result = subprocess.run([softhsm_setup, cmd], stdout=subprocess.PIPE)
        return result.stdout, result.returncode

    @pytest.mark.integration
    def test_softhsm(self, tmp_path: pathlib.Path) -> None:
        if shutil.which("softhsm2-util") is None:
            return

        did_setup = False

        stdout_b, returncode = self.run_softhsm_setup("getkeyuri")
        if returncode > 0:
            stdout_b, _ = self.run_softhsm_setup("setup")
            if stdout_b is None:
                return

            did_setup = True

        try:
            stdout = str(stdout_b.rstrip())
            i = stdout.index("pkcs11:")
            pkcs11_uri = stdout[i:].rstrip("'")

            stdout, _ = self.run_softhsm_setup("getpubkey")

            pub_key_file = tmp_path.joinpath("pubkey.pem")
            pub_key_file.write_bytes(stdout)

            model_path = tmp_path
            signature = tmp_path.joinpath("model.sig")

            model_signing.signing.Config().use_pkcs11_signer(
                pkcs11_uri=pkcs11_uri, module_paths=MODULE_PATHS
            ).set_hashing_config(
                model_signing.hashing.Config().set_ignored_paths(
                    paths=[signature]
                )
            ).sign(model_path, signature)

            model_signing.verifying.Config().use_elliptic_key_verifier(
                public_key=pub_key_file
            ).set_hashing_config(
                model_signing.hashing.Config().set_ignored_paths(
                    paths=[signature]
                )
            ).verify(model_path, signature)
        finally:
            if did_setup:
                self.run_softhsm_setup("teardown")
