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
"""Functionality to parse PKCS #11 URIs and access its components."""

from collections.abc import Iterable
import glob
import os
from os import stat
import re
from stat import S_ISREG
from urllib import parse
from urllib.parse import urlparse

import PyKCS11


def escape_all(s: str) -> str:
    """PCT-escape all characters in the given string; used primarily for Id."""
    res = ""
    for c in s:
        o = ord(c) & 0xFF
        res += f"%{o:02X}"

    return res


def escape(s: str, is_path: bool) -> str:
    """PCT-escape the given string considering path or query attribute."""
    res = ""
    for c in s:
        if (
            (
                (c >= "a" and c <= "z")
                or (c >= "A" and c <= "Z")
                or (c >= "0" and c <= "9")
            )
            or (is_path and c == "&")
            or (not is_path and (c in ["/", "?", "|"]))
        ):
            res += c
        else:
            if c in ["-", ".", "_", "~"] or c in [
                ":",
                "[",
                "]",
                "@",
                "!",
                "$",
                "'",
                "(",
                ")",
                "*",
                "+",
                ",",
                "=",
            ]:  # unreserved per RFC 3986 sec. 2.3
                res += c
            else:
                o = ord(c) & 0xFF
                res += f"%{o:02X}"

    return res


class Pkcs11URI:
    def __init__(self):
        self.reset()
        self.module_directories = []
        self.allowed_module_paths = []
        self.allow_any_module = True

    def reset(self) -> None:
        """Clear path and query parameters of the URI."""
        self.path_attributes = {}
        self.query_attributes = {}

    def get_attribute_bytes(
        self, attr_map: dict[str, str], name: str
    ) -> bytes | None:
        """Get an attribute in form of bytes, if available."""
        if name not in attr_map:
            return None
        vb = b""
        for c in attr_map[name]:
            vb += ord(c).to_bytes(length=1, byteorder="big")
        return vb

    def get_path_attribute_bytes(self, name: str) -> bytes | None:
        """Get a path attribute as <bytes>."""
        return self.get_attribute_bytes(self.path_attributes, name)

    def get_query_attribute_bytes(self, name: str) -> bytes | None:
        """Get a query attribute as <bytes>."""
        return self.get_attribute_bytes(self.query_attributes, name)

    def set_attribute(
        self,
        attr_map: dict[str, str],
        name: str,
        value: str,
        is_path: bool = False,
        pctencode: bool = False,
    ) -> None:
        if pctencode:
            value = escape(value, is_path)
        """Set an attribute in the given dictionary."""
        # RFC7512 section 2.3: only 'id' may contain non-textual data
        # However, URI on page 15 shows a token with 'acute:%20>>%C3%A1<<' in
        # the name.
        # -> Only 'id' is relevant for user to have as bytes, all other ones can
        #    be given back as strings or pct-encoded
        vb = parse.unquote_to_bytes(value)

        v = ""
        for c in vb:
            v += chr(c)
        attr_map[name] = v

    def get_path_attribute(
        self, name: str, pctencode: bool = False
    ) -> str | None:
        """Get a path attribute by its name, possibly in pct-encode form."""
        v = self.path_attributes.get(name)
        if v is not None and pctencode:
            v = escape(v, True)
        return v

    def set_path_attribute(
        self, name: str, value: str, pctencode: bool = False
    ) -> None:
        """Set a path attribute."""
        self.set_attribute(self.path_attributes, name, value, True, pctencode)

    def set_path_attribute_unencoded(self, name: str, value: bytes) -> None:
        """Set an unencoded path attribute as bytes."""
        self.set_path_attribute(name, value.decode("utf-8"), True)

    def add_path_attribute(
        self, name: str, value: str, pctencode: bool = False
    ) -> None:
        """Add a path attrbuute given as a string."""
        if name in self.path_attributes:
            raise ValueError("duplicate path attribute")
        self.set_path_attribute(name, value, pctencode)

    def add_path_attribute_unencoded(self, name: str, value: bytes) -> None:
        """Add an unencoded path attribute as bytes."""
        if name in self.path_attributes:
            raise ValueError("duplicate path attribute")
        self.set_path_attribute_unencoded(name, value)

    def remove_path_attribute(self, name: str) -> None:
        """Remove a path attribute."""
        if name in self.path_attributes:
            del self.path_attributes[name]

    def get_query_attribute(
        self, name: str, pctencode: bool = False
    ) -> str | None:
        """Get a query attribute by its name, possibly in pct-encode form."""
        v = self.query_attributes.get(name)
        if v is not None and pctencode:
            v = escape(v, False)
        return v

    def set_query_attribute(
        self, name: str, value: str, pctencode: bool = False
    ) -> None:
        """Set a query attribute."""
        self.set_attribute(self.query_attributes, name, value, False, pctencode)

    def set_query_attribute_unencoded(self, name: str, value: bytes) -> None:
        """Set an unencoded query attribute as bytes."""
        self.set_query_attribute(name, value.decode("utf-8"), True)

    def add_query_attribute(
        self, name: str, value: str, pctencode: bool = False
    ) -> None:
        """Add a query attribute given as a string. pctencode it if wanted."""
        if name in self.query_attributes:
            raise ValueError("duplicate query attribute")
        self.set_query_attribute(name, value, pctencode)

    def add_query_attribute_unencoded(self, name: str, value: bytes) -> None:
        """Add an unencoded query attribute as bytes."""
        if name in self.query_attributes:
            raise ValueError("duplicate query attribute")
        self.set_query_attribute_unencoded(name, value)

    def remove_query_attribute(self, name: str) -> None:
        """Remove a query attribute."""
        if name in self.query_attributes:
            del self.query_attributes[name]

    def validate(self) -> None:
        """Validate a Pkcs11URI.

        Validate a Pkcs11URI object's attributes following RFC 7512 rules and
        proper formatting of their values.
        """
        v = self.path_attributes.get("slot-id")
        if v is not None and not any(i.isdigit() for i in v):
            raise ValueError(f"slot-id must be a number: {v}")

        v = self.path_attributes.get("library-version")
        if v is not None and re.match("^[0-9]+(\\.[0-9]+)?$", v) is None:
            raise ValueError(f"Invalid format for library-version '{v}'")

        v = self.path_attributes.get("type")
        if (
            v is not None
            and re.match("^(public|private|cert|secret-key|data)?$", v) is None
        ):
            raise ValueError(f"Invalid type '{v}'")

        v1 = self.query_attributes.get("pin-source")
        v2 = self.query_attributes.get("pin-value")
        if v1 is not None and v2 is not None:
            raise ValueError("URI must not contain pin-source and pin-value")

        v = self.query_attributes.get("module-path")
        if v is not None and not os.path.isabs(v):
            raise ValueError(
                f"path {v} of module-path attribute must be absolute"
            )

    def has_pin(self) -> bool:
        """Check whether a PIN has been provided."""
        return (
            self.query_attributes.get("pin-value") is not None
            or self.query_attributes.get("pin-source") is not None
        )

    def get_pin(self) -> str:
        """Get the PIN to access an object for example."""
        v = self.query_attributes.get("pin-value")
        if v is not None:
            return v

        v = self.query_attributes.get("pin-source")
        if v is not None:
            up = urlparse(v)
            if up.scheme in ["", "file"]:
                if not os.path.isabs(up.path):
                    raise ValueError(
                        f"PIN URI path '{up.path}' is not absolute"
                    )
                with open(up.path) as f:
                    return f.read()
            else:
                raise ValueError(
                    f"PIN URI scheme {up.scheme} is not supported: {{v}}"
                )

        raise ValueError("Neither pin-source nor pin-value are available")

    def parse(self, uri: str) -> None:
        """Parse the given URI."""
        if not uri.startswith("pkcs11:"):
            raise ValueError(
                f"Malformed pkcs11 URI: missing 'pkcs11:' prefix: {uri}"
            )

        self.reset()

        parts = uri[7:].split("?", 1)

        if len(parts[0]) > 0:
            # parse path part
            for part in parts[0].split(";"):
                p = part.split("=", 1)
                if len(p) != 2:
                    raise ValueError(
                        "Malformed pkcs11 URI: malformed path attribute"
                    )
                self.add_path_attribute(p[0], p[1])

        if len(parts) == 2:
            for part in parts[1].split("&"):
                p = part.split("=", 1)
                if len(p) != 2:
                    raise ValueError(
                        "Malformed pkcs11 URI: malformed query attribute"
                    )
                self.add_query_attribute(p[0], p[1])

        self.validate()

    def format_attributes(self, attr_map: dict[str, str], is_path: bool) -> str:
        """Format the attributes in the given map."""
        res = ""
        for key, value in attr_map.items():
            value = escape_all(value) if key == "id" else escape(value, is_path)
            if len(res) > 0:
                if is_path:
                    res += ";"
                else:
                    res += "&"
            res += key + "=" + value
        return res

    def format(self) -> str:
        """Format the Pkcs11URI to a string."""
        self.validate()
        result = "pkcs11:" + self.format_attributes(self.path_attributes, True)
        if len(self.query_attributes) > 0:
            result += "?" + self.format_attributes(self.query_attributes, False)
        return result

    def __str__(self) -> str:
        return self.format()

    def set_module_directories(self, dirs: Iterable[str]) -> None:
        """Set directories to search for pkcs11 modules."""
        self.module_directories = dirs

    def set_allowed_module_paths(self, allowed_paths: list[str]) -> None:
        """Set the allowed paths for pkcs11 modules."""
        self.allowed_module_paths = allowed_paths

    def set_allow_any_module(self, allow_any_module: bool) -> None:
        """Set the any module may be loaded."""
        self.allow_any_module = allow_any_module

    def _is_allowed_path(self, path: str, allowed_paths: list[str]) -> bool:
        """Check whether the given path is allowed."""
        if self.allow_any_module:
            return True
        for allowed_path in allowed_paths:
            if allowed_path == path:
                return True
            print(allowed_path)
            if allowed_path[-1] == os.path.sep and path.find(allowed_path) == 0:
                try:
                    path[len(allowed_path) :].index(os.path.sep)
                except ValueError:
                    return True
        return False

    def get_module(self) -> str:
        """Get the pkcs11 module that is to be used."""
        v = self.get_query_attribute("module-path")
        if v is not None:
            try:
                statbuf = stat(v)
                if S_ISREG(statbuf.st_mode):
                    if self._is_allowed_path(v, self.allowed_module_paths):
                        return v
                    raise ValueError(
                        f"module-path '{v}' is not allowed by policy"
                    )
                if not os.path.isdir(v):
                    raise ValueError(
                        f"module-path '{v}' points to an invlaid file type"
                    )
                searchdirs = [v]

            except FileNotFoundError as err:
                raise ValueError from err
        else:
            searchdirs = self.module_directories

        module_name = self.get_query_attribute("module-name")
        if module_name is None:
            raise ValueError("module-name attribute is not set")
        module_name = module_name.lower()

        for dir in searchdirs:
            files = glob.glob(os.path.join(dir, "*"))
            for file in files:
                file_lower = file.lower()
                try:
                    i = file_lower.index(module_name)
                except ValueError:
                    continue

                if (
                    len(file_lower) == i + len(module_name)
                    or file_lower[i + len(module_name)] == "."
                ):
                    f = os.path.join(dir, file)
                    if self._is_allowed_path(f, self.allowed_module_paths):
                        return f
                    raise ValueError(f"module '{f}' is not allowed by policy")
        dirs = ", ".join(searchdirs)
        raise ValueError(f"No module '{module_name}' could be found in {dirs}")

    def get_keyid_and_label(self) -> tuple[bytes | None, str | None]:
        """Get the id for the key and its label."""
        keyid = self.get_path_attribute_bytes("id")
        label = self.get_path_attribute("object")
        if keyid is None and label is None:
            raise ValueError(
                "Neither 'id' nor 'object' attributes were found in pkcs11 URI"
            )
        return keyid, label

    def open_session(
        self,
        lib: PyKCS11.PyKCS11Lib,
        slot_id: int,
        pin: str,
        token_label: str | None,
    ) -> PyKCS11.Session:
        """Open a session.

        Open a session given a slot-id and an optional token label whose name
        must match if given.
        """
        token = lib.getTokenInfo(slot_id)
        if token_label is not None and token.label != f"{token_label:<32s}":
            raise ValueError(
                f"The token in slot {slot_id} is not called '{token_label}'"
            )
        session = lib.openSession(slot_id)
        if pin is not None:
            session.login(pin)
        return session

    def get_login_parameters(self) -> tuple[str | None, str, int]:
        """Get the login parameters PIN, module, and slot-id from the URI."""
        pin = None
        if self.has_pin():
            pin = self.get_pin()

        module = self.get_module()

        slotid = -1
        v = self.get_path_attribute("slot-id")
        if v is not None:
            slotid = int(v)
            if slotid < 0:
                raise ValueError("slot-id is a negative number")
            if slotid > 0xFFFFFFFF:
                raise ValueError("slot-id is larger than 32 bit")

        return pin, module, slotid

    def login(self) -> tuple[PyKCS11.Session, PyKCS11.PyKCS11Lib]:
        """Log in to the device using parameters from the URI."""
        pin, module, slot_id = self.get_login_parameters()

        lib = PyKCS11.PyKCS11Lib().load(pkcs11dll_filename=module)

        token_label = self.get_path_attribute("token")

        # If a slot-id is given, use it to open the session
        if slot_id >= 0:
            return self.open_session(lib, slot_id, pin, token_label), lib

        if token_label is None:
            raise ValueError("Need a token due to missing slot-id")

        for slot in lib.getSlotList():
            token = lib.getTokenInfo(slot)
            if token.label == f"{token_label:<32s}":
                session = lib.openSession(slot)
                if pin is not None:
                    session.login(pin)
                return session, lib
        raise ValueError(
            f"Could not find a token with label {token_label} in any slots"
        )
