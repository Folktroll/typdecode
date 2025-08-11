#!/usr/bin/env python3

# This is a almost full Python rewrite of a Perl tool originally created by misch (http://ati.land.cz/)
# Original work licensed under BSD 3-Clause License.

# Modified, rewritten, and improved in 2025 by Folk Trool through reverse engineering
# and original research.
# Licensed under the MIT License (see LICENSE file for details).

# DISCLAIMER:
# This software is a Work in Progress (WIP) and Proof of Concept (POC).
# It is created solely for educational purposes and experimentation.
# Not intended for production use.

"""typ_decode."""

from __future__ import annotations

import argparse
import binascii
import os
import struct
import sys
import traceback
from pathlib import Path
from typing import Any, ClassVar

VERSION = "1.0"
DEBUG = True


class TypDecode:
    @staticmethod
    def signature() -> str:
        return f"; typdecode v{VERSION} created by Folk Trool, 2025\n"

    @staticmethod
    def hexdump(data: bytes) -> str:
        if not data:
            return "; (empty block)\n"
        hex_str = binascii.hexlify(data).decode("ascii")
        lines = [hex_str[i : i + 32] for i in range(0, len(hex_str), 32)]
        return "\n".join(f"; {line}" for line in lines) + "\n"

    @staticmethod
    def checkcustomcolor(byte_value: int) -> int:
        mask: int = 0x18  # 3 or 4 bit
        bits = (byte_value & mask) >> 3
        return [0, 1, 2][bin(bits).count("1")]


class GarminTYP:
    DEBUG_OFFSETS = 0x0001
    DEBUG_LONG_HEADER = 0x0002

    def __init__(self, raw_data: bytes, debug_flags: int = 0) -> None:
        self._errors: list[str] = []
        self._debug = debug_flags
        self._header = Header(self, raw_data)
        self._polyplaceholders = Collection(self, "polyplaceholder", raw_data)
        self._draworder = DrawOrder(self, self._header.raw_draworder)
        self._polygons = Collection(self, "polygon", raw_data)
        self._lines = Collection(self, "line", raw_data)
        self._points = Collection(self, "point", raw_data)
        self._nt1_points = Collection(self, "NT1point", raw_data)
        self._nt_blocks = NTBlocks(self)
        self._spaces_data = None

    @property
    def spaces_data(self) -> dict | None:
        return self._spaces_data

    def debug_offsets(self) -> bool:
        return bool(self._debug & self.DEBUG_OFFSETS)

    def debug_long_header(self) -> bool:
        return bool(self._debug & self.DEBUG_LONG_HEADER)

    def header(self) -> Header:
        return self._header

    def lines(self) -> Collection:
        return self._lines

    def points(self) -> Collection:
        return self._points

    def nt1points(self) -> Collection:
        return self._nt1_points

    def polygons(self) -> Collection:
        return self._polygons

    def polyplaceholders(self) -> Collection:
        return self._polyplaceholders

    def draworder(self) -> DrawOrder:
        return self._draworder

    def nt_blocks(self) -> NTBlocks:
        return self._nt_blocks

    def clear_errors(self) -> None:
        self._errors = []

    def error(self, err: str) -> None:
        if err not in self._errors:
            self._errors.append(err)

    def error_list(self) -> list[str]:
        return self._errors

    def collection_by_kind(self, kind: str) -> Collection:
        collections = {
            "polyplaceholder": self.polyplaceholders,
            "polygon": self.polygons,
            "line": self.lines,
            "point": self.points,
            "NT1point": self.nt1points,
        }
        if kind not in collections:
            msg = f"FATAL: unknown kind: {kind}"
            print(msg)
            raise ValueError(msg)
        return collections[kind]()

    def pid(self) -> int:
        return self.header().pid()

    def fid(self) -> int:
        return self.header().fid()

    def write_str(self, filename: str) -> None:
        content = ""
        if self.error_list():
            content += "; !!!!!!!!! TYP contained errors: !!!!!!!!!\n"
            content += "".join(f"; {err}\n" for err in self.error_list())
            content += "; !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\n\n"
        content += self.header().write_str()
        content += (
            self.nt_blocks().write_str()
            + self.draworder().write_str()
            + self.polygons().write_str("polygons")
            + self.lines().write_str("lines")
            + self.points().write_str("points")
            + self.nt1points().write_str("")
        )
        with Path(filename).open("w", encoding="utf-8") as f:
            f.write(content)
        if len(content) < 5000:  # DEBUG MODE
            print(content)
        print("✅ Your decompiled file is ready.")

    def language_codes(self) -> dict[int, str]:
        return {
            0x00: "unspecified",
            0x01: "french",
            0x02: "german",
            0x03: "dutch",
            0x04: "english",
            0x05: "italian",
            0x06: "finnish",
            0x07: "swedish",
            0x08: "spanish",
            0x09: "basque",
            0x0A: "catalan",
            0x0B: "galician",
            0x0C: "welsh",
            0x0D: "gaelic",
            0x0E: "danish",
            0x0F: "norwegian",
            0x10: "portuguese",
            0x11: "slovak",
            0x12: "czech",
            0x13: "croatian",
            0x14: "hungarian",
            0x15: "polish",
            0x16: "turkish",
            0x17: "greek",
            0x18: "slovenian",
            0x19: "russian",
            0x1A: "estonian",
            0x1B: "latvian",
            0x1C: "romanian",
            0x1D: "albanian",
            0x1E: "bosnian",
            0x1F: "lithuanian",
            0x20: "serbian",
            0x21: "macedonian",
            0x22: "bulgarian",
        }

    def as_binary(self) -> bytes:
        self.polygons().recalculate()
        self.lines().recalculate()
        self.points().recalculate()
        self.nt1points().recalculate()
        self.header().recalculate()
        return (
            self.header().as_binary()
            + self.polygons().as_binary()
            + self.lines().as_binary()
            + self.points().as_binary()
            + self.nt1points().as_binary()
            + self.draworder().as_binary()
            + self.nt_blocks().as_binary()
        )


class Header:
    def __init__(self, parent: GarminTYP, raw_data: bytes) -> None:
        self._parent = parent
        self._raw_draworder = b""
        self._signpost = {}
        self._format = "OLD"
        self._nt1 = None
        self._nt2 = None
        self._filler = b""
        self._diffvalue = None

        if not raw_data:
            self.length = 91
            self._version = 1
            self._timestamp = struct.pack("HBBBBB", 2000 - 1900, 0, 1, 0, 0, 0)
            self._codepage = 1252
            self._fid = 0
            self._pid = 0
            self._signpost = {
                "draworder": {"arrayofs": 0, "arraymod": 5, "arraysize": 0},
                "point": {"dataofs": 0, "datalen": 0, "arrayofs": 0, "arraymod": 4, "arraysize": 0},
                "NT1point": {"dataofs": 0, "datalen": 0, "arrayofs": 0, "arraymod": 0, "arraysize": 0},
                "line": {"dataofs": 0, "datalen": 0, "arrayofs": 0, "arraymod": 4, "arraysize": 0},
                "polygon": {"dataofs": 0, "datalen": 0, "arrayofs": 0, "arraymod": 4, "arraysize": 0},
            }
            self._raw_draworder = b""
        else:
            self.length = struct.unpack("<H", raw_data[:2])[0]
            if raw_data[2:12] != b"GARMIN TYP":
                msg = f"Not a Garmin TYP file: {raw_data[2:12].decode('ascii', errors='ignore')}"
                raise ValueError(msg)
            self._version = struct.unpack("<H", raw_data[12:14])[0]
            self._timestamp = raw_data[14:21]
            self._codepage = struct.unpack("<H", raw_data[21:23])[0]
            if len(raw_data) < 91:
                msg = f"raw_data too short: {len(raw_data)} bytes, expected at least 91"
                raise ValueError(msg)
            if len(raw_data[23:85]) != 62:
                msg = f"Header slice [23:91] is {len(raw_data[23:91])} bytes, expected 68"
                raise ValueError(msg)
            header_data = struct.unpack("<6L2H1L1H2L1H2L1H2L1H1L", raw_data[23:91])
            self._fid = header_data[6]
            self._pid = header_data[7]
            self._signpost = {
                "draworder": {"arrayofs": header_data[17], "arraymod": header_data[18], "arraysize": header_data[19]},
                "point": {
                    "dataofs": header_data[0],
                    "datalen": header_data[1],
                    "arrayofs": header_data[8],
                    "arraymod": header_data[9],
                    "arraysize": header_data[10],
                },
                "NT1point": {"dataofs": 0, "datalen": 0, "arrayofs": 0, "arraymod": 0, "arraysize": 0},
                "line": {
                    "dataofs": header_data[2],
                    "datalen": header_data[3],
                    "arrayofs": header_data[11],
                    "arraymod": header_data[12],
                    "arraysize": header_data[13],
                },
                "polygon": {
                    "dataofs": header_data[4],
                    "datalen": header_data[5],
                    "arrayofs": header_data[14],
                    "arraymod": header_data[15],
                    "arraysize": header_data[16],
                },
            }
            self._raw_draworder = raw_data[
                self._signpost["draworder"]["arrayofs"] : self._signpost["draworder"]["arrayofs"] + self._signpost["draworder"]["arraysize"]
            ]
            remaining = self.length - 0x5B
            if remaining > 0:
                buf = raw_data[0x5B : 0x5B + remaining]
                if remaining >= 0x13:
                    self._format = "NT"
                    nt1_data = struct.unpack("<IHI3B2I", raw_data[0x5B:0x6E])
                    self._signpost["NT1point"] = {
                        "arrayofs": nt1_data[0],
                        "arraymod": nt1_data[1],
                        "arraysize": nt1_data[2],
                        "dataofs": nt1_data[5],
                        "datalen": nt1_data[6],
                    }
                    self._nt1 = {"y": nt1_data[3]}
                    remaining -= 0x13
                if remaining >= 0x2E:
                    self._format = "NT2"
                    nt2_data = struct.unpack("<12I", raw_data[0x6E:0x9C])
                    block0 = raw_data[nt2_data[1] : nt2_data[1] + nt2_data[2]]
                    block1 = raw_data[nt2_data[5] : nt2_data[5] + nt2_data[6]]
                    block2 = raw_data[nt2_data[9] : nt2_data[9] + nt2_data[10]]
                    self._nt2 = {
                        "block0": block0,
                        "block1": block1,
                        "block2": block2,
                        "x": nt2_data[0],
                        "y": nt2_data[3],
                        "z": nt2_data[4],
                        "u": nt2_data[7],
                        "v": nt2_data[8],
                        "w": nt2_data[11],
                    }
                    remaining -= 0x2E
                if remaining > 0:
                    self._format = "UNKNOWN"
                    self._nt1 = None
                    self._nt2 = None
                    self._filler = buf

    def parent(self) -> GarminTYP:
        return self._parent

    @property
    def nt1(self: Header) -> dict | None:
        return self._nt1

    @property
    def nt2(self: Header) -> dict | None:
        return self._nt2

    @property
    def raw_draworder(self) -> bytes:
        return self._raw_draworder

    @property
    def signpost(self) -> dict:
        return self._signpost

    def pid(self, new: int | None = None) -> int:
        if new is not None:
            if not 0 <= new <= 65535:
                self.parent().error(f"Product ID must be in range 0 - 65535, not {new}")
            else:
                self._pid = new
        return self._pid

    def fid(self, new: int | None = None) -> int:
        if new is not None:
            if not 0 <= new <= 65535:
                self.parent().error(f"Family ID must be in range 0 - 65535, not {new}")
            else:
                self._fid = new
        return self._fid

    def version(self, new: int | None = None) -> int:
        if new is not None:
            self._version = new
        return self._version

    def codepage(self, new: int | None = None) -> int:
        if new is not None:
            if not str(new).isdigit():
                self.parent().error(f"Invalid codepage, must contain only digits: {new}")
            elif not 1250 <= new <= 1258:
                self.parent().error(f"Invalid codepage, must be 1250 - 1258: {new}")
            else:
                self._codepage = new
        return self._codepage

    def format(self, type1: str | None = None) -> str:
        if type1:
            if type1 == "OLD":
                if self._format != "OLD":
                    self._format = type1
                    self._filler = b""
                    self.length = 0x5B
            elif type1 == "NT":
                if self._format != "NT":
                    self._format = type1
                    self._filler = b""
                    self._nt1 = {"y": 0x1F}
                    self.length = 0x6E
            elif type1 == "NT2":
                if self._format != "NT2":
                    self._format = type1
                    self._filler = b""
                    self._nt1 = {"y": 0x1F}
                    self._nt2 = {
                        "block0": b"",
                        "block1": b"",
                        "block2": b"",
                        "x": 0,
                        "y": 0,
                        "z": 0,
                        "u": 0,
                        "v": 0,
                        "w": 0,
                    }
                    self.length = 0x9C
            else:
                msg = f"unsupported header type, cannot save in this format: {type1}"
                raise ValueError(msg)
        return self._format

    def timestamp(self, new: str | None = None) -> dict[str, int]:
        if new:
            try:
                yyyy, mm, dd, hh, mi, ss = map(int, new.replace(":", "-").split("-"))
                self._timestamp = struct.pack("HBBBBB", yyyy - 1900, mm - 1, dd, hh, mi, ss)
            except ValueError:
                msg = f"Invalid format of timestamp: {new}"
                raise ValueError(msg) from None
        yyyy, mm, dd, hh, mi, ss = struct.unpack("HBBBBB", self._timestamp)
        mm += 1
        if yyyy <= 200:
            yyyy += 1900
        return {"y": yyyy, "m": mm, "d": dd, "hh": hh, "mm": mi, "ss": ss}

    def recalculate(self) -> int:
        r = self._signpost
        pos = self.length

        r["polygon"]["dataofs"] = pos
        r["polygon"]["datalen"] = self.parent().polygons().datalength()
        pos += r["polygon"]["datalen"]
        r["polygon"]["arrayofs"] = pos
        r["polygon"]["arraysize"] = self.parent().polygons().infolength()
        pos += r["polygon"]["arraysize"]

        r["line"]["dataofs"] = pos
        r["line"]["datalen"] = self.parent().lines().datalength()
        pos += r["line"]["datalen"]
        r["line"]["arrayofs"] = pos
        r["line"]["arraysize"] = self.parent().lines().infolength()
        pos += r["line"]["arraysize"]

        r["point"]["dataofs"] = pos
        r["point"]["datalen"] = self.parent().points().datalength()
        pos += r["point"]["datalen"]
        r["point"]["arrayofs"] = pos
        r["point"]["arraysize"] = self.parent().points().infolength()
        pos += r["point"]["arraysize"]

        r["NT1point"]["dataofs"] = pos
        r["NT1point"]["datalen"] = self.parent().nt1points().datalength()
        pos += r["NT1point"]["datalen"]
        r["NT1point"]["arrayofs"] = pos
        r["NT1point"]["arraysize"] = self.parent().nt1points().infolength()
        pos += r["NT1point"]["arraysize"]

        for kind in ("polygon", "line", "point", "NT1point"):
            if r[kind]["datalen"] == 0:
                r[kind]["dataofs"] = 0
            if r[kind]["arraysize"] == 0:
                r[kind]["arrayofs"] = 0

        r["draworder"]["arrayofs"] = pos
        r["draworder"]["arraysize"] = self.parent().draworder().length()
        pos += r["draworder"]["arraysize"]
        if r["draworder"]["arraysize"] == 0:
            r["draworder"]["arrayofs"] = 0

        if self._format == "NT2" and self._nt2 is not None:
            nt2 = self._nt2
            nt2["block0_pos"] = pos if len(nt2["block0"]) > 0 else 0
            pos += len(nt2["block0"])
            nt2["block1_pos"] = pos if len(nt2["block1"]) > 0 else 0
            pos += len(nt2["block1"])
            nt2["block2_pos"] = pos if len(nt2["block2"]) > 0 else 0
            pos += len(nt2["block2"])

        return pos

    def as_binary(self) -> bytes:
        ret = b""
        ret += struct.pack("<H", self.length)
        ret += b"GARMIN TYP"
        ret += struct.pack("<H", self._version)
        ret += self._timestamp
        ret += struct.pack("<H", self._codepage)
        ret += struct.pack(
            "<6I2H4I3I3I2I",
            self._signpost["point"]["dataofs"],
            self._signpost["point"]["datalen"],
            self._signpost["line"]["dataofs"],
            self._signpost["line"]["datalen"],
            self._signpost["polygon"]["dataofs"],
            self._signpost["polygon"]["datalen"],
            self._fid,
            self._pid,
            self._signpost["point"]["arrayofs"],
            self._signpost["point"]["arraymod"],
            self._signpost["point"]["arraysize"],
            self._signpost["line"]["arrayofs"],
            self._signpost["line"]["arraymod"],
            self._signpost["line"]["arraysize"],
            self._signpost["polygon"]["arrayofs"],
            self._signpost["polygon"]["arraymod"],
            self._signpost["polygon"]["arraysize"],
            self._signpost["draworder"]["arrayofs"],
            self._signpost["draworder"]["arraymod"],
            self._signpost["draworder"]["arraysize"],
        )
        if self._format in ("NT", "NT2") and self._nt1 is not None:
            nt1 = self._nt1
            ret += struct.pack(
                "<IHI3B2I",
                self._signpost["NT1point"]["arrayofs"],
                self._signpost["NT1point"]["arraymod"],
                self._signpost["NT1point"]["arraysize"],
                nt1["y"],
                0,
                0,
                self._signpost["NT1point"]["dataofs"],
                self._signpost["NT1point"]["datalen"],
            )
        if self._format == "NT2" and self._nt2 is not None:
            nt2 = self._nt2
            ret += struct.pack(
                "<12I",
                nt2["x"],
                nt2["block0_pos"],
                len(nt2["block0"]),
                nt2["y"],
                nt2["z"],
                nt2["block1_pos"],
                len(nt2["block1"]),
                nt2["u"],
                nt2["v"],
                nt2["block2_pos"],
                len(nt2["block2"]),
                nt2["w"],
            )
        ret += self._filler
        return ret

    def write_str(self, for_diff: bool = False) -> str:
        ret = ""
        if not for_diff:
            ret += f"; THIS FILE WAS CREATED BY pytdecode v{VERSION}\n"
        yyyy, mm, dd, hh, mi, ss = struct.unpack("HBBBBB", self._timestamp)

        creator = "Garmin MPC" if yyyy <= 200 else "cGPSmapper"
        spaces_data = self.parent().spaces_data
        if spaces_data is not None:
            for sd in spaces_data:
                if sd["data"].startswith(b"MapTk"):
                    creator = sd["data"].decode("ascii", errors="ignore").rstrip("\x00")
        ret += (
            f"; Original TYP was created {dd}.{mm + 1}.{1900 + yyyy if yyyy <= 200 else yyyy} at {hh:02d}:{mi:02d}:{ss:02d}, probably with {creator}\n"
            f"; Version={self._version}\n"
            f"; Header length: 0x{self.length:04x} bytes, header format: {self._format}\n"
        )
        if not for_diff:
            ret += "; Header dump:\n"
            for kind in ("draworder", "polygon", "point", "line", "NT1point"):
                h = self._signpost[kind]
                if kind == "draworder":
                    ret += (
                        f"; {kind:10s}: {'':38s} info@0x{h['arrayofs']:06x}-0x{h['arrayofs'] + h['arraysize'] - 1 if h['arraysize'] else 0:06x} "
                        f"(elem_size={h['arraymod']}, #elements={h['arraysize'] // h['arraymod'] if h['arraymod'] else 0})\n"
                    )
                else:
                    ret += (
                        f"; {kind:10s}: data@0x{h['dataofs']:06x}-0x{h['dataofs'] + h['datalen'] - 1 if h['datalen'] else 0:06x} "
                        f"(len=0x{h['datalen']:06x}), info@0x{h['arrayofs']:06x}-0x{h['arrayofs'] + h['arraysize'] - 1 if h['arraysize'] else 0:06x} "
                        f"(elem_size={h['arraymod']}, #elements={h['arraysize'] // h['arraymod'] if h['arraymod'] else 0})\n"
                    )
            ret += "\n"
        ret += "[_id]\n"
        ret += f"ProductCode={self._pid}\nFID={self._fid}\nCodePage={self._codepage}\n"
        if self._filler:
            ret += "; unknown data in header:\n" + TypDecode.hexdump(self._filler) + "\n"
        ret += "[end]\n\n\n"
        return ret

    def as_diffvalue(self) -> str | None:
        if not hasattr(self, "_diffvalue"):
            self._diffvalue = self.write_str(True)
        return self._diffvalue


class Collection:
    def __init__(self, parent: GarminTYP, kind: str, raw_data: bytes) -> None:
        self._parent = parent
        self._kind = kind
        self._persistent_id = 0
        self._elements: list[Any] = []
        self._xelemref_by_id: dict[str, Any] = {}

        if kind == "polyplaceholder":
            return

        r = parent.header().signpost[kind]

        buf = raw_data[r["dataofs"] : r["dataofs"] + r["datalen"]]
        full_content = buf

        elements = []

        if r["arraysize"] > 0:
            array_buf = raw_data[r["arrayofs"] : r["arrayofs"] + r["arraysize"]]
            elements_count = r["arraysize"] // r["arraymod"]

            for i in range(elements_count):
                mod = r["arraymod"]
                start_idx = mod * i
                tmp = array_buf[start_idx : start_idx + mod]

                if mod == 6:
                    otype, offset, ofs_hi = struct.unpack("<HHH", tmp)
                    offset += ofs_hi << 16
                elif mod == 5:
                    otype, offset, ofs_hi = struct.unpack("<HHB", tmp)
                    offset += ofs_hi << 16
                elif mod == 4:
                    otype, offset = struct.unpack("<HH", tmp)
                elif mod == 3:
                    otype, offset = struct.unpack("<HB", tmp)
                else:
                    msg = f"Unknown arraymod length: {mod}"
                    raise ValueError(msg)

                wtype = (otype >> 5) | ((otype & 0x1F) << 11)
                type1 = wtype & 0x7FF
                subtype = wtype >> 11

                elements.append({"offset": offset, "type": type1, "subtype": subtype})

        elements.sort(key=lambda x: x["offset"])

        out_elements = []
        dupcheck = {}

        for i, p in enumerate(elements):
            block_length = elements[i + 1]["offset"] - p["offset"] if i < len(elements) - 1 else r["datalen"] - p["offset"]

            dupkey = f"{kind}/{p['type']}/{p['subtype']}"
            dupcheck[dupkey] = dupcheck.get(dupkey, 0) + 1
            if dupcheck[dupkey] > 1:
                self.parent().error(f"File contains multiple definitions of {kind} type=0x{p['type']:03x}/0x{p['subtype']:02x}.")

            objtype_map = {
                "polygon": Polygon,
                "line": Line,
                "point": Point,
                "NT1point": NT1Point,
            }

            if kind not in objtype_map:
                msg = f"Unknown element kind: {kind}"
                raise ValueError(msg)

            objtype = objtype_map[kind]

            content = full_content[p["offset"] : p["offset"] + block_length]

            if len(content) == 0:
                self.parent().error(f"File contains empty element ({kind}#{i}, type=0x{p['type']:03x}/0x{p['subtype']:02x}). You are editing damaged TYP file!")
                continue

            elem = objtype(self, p["type"], p["subtype"], content)
            elem.orig_offset = p["offset"]

            out_elements.append(elem)

        for elem in out_elements:
            elem_id = f"{elem.type}_{elem.subtype}"
            self.add_element(elem, elem_id)

    def parent(self) -> GarminTYP:
        return self._parent

    def kind(self) -> str:
        return self._kind

    def add_element(self, element: str | PolyPlaceholder, id1: str) -> None:
        self._elements.append(element)
        self._xelemref_by_id[id1] = element

    def iterate(self) -> list[Any]:
        return self._elements

    def datalength(self) -> int:
        return sum(len(elem.data_as_binary()) for elem in self._elements)

    def infolength(self) -> int:
        return len(self._elements) * 4

    def recalculate(self) -> None:
        pass

    def as_binary(self) -> bytes:
        return b"".join(elem.data_as_binary() for elem in self._elements)

    def write_str(self, section: str) -> str:
        ret = f";====================== {section.upper()} ==========================\n\n\n"
        for elem in self._elements:
            ret += elem.write_str()
        return ret


class Element:
    def __init__(self, parent: Collection, type_: int, subtype: int, content_data: bytes | None) -> None:
        self._parent = parent
        self._type = type_
        self._subtype = subtype
        self._orig_offset = 0
        self._has_l18n = False
        self._fontsize = -1
        self._more_info = None
        self._color_type = 0
        self._colors = []
        self._orientation = False
        self._width = 0
        self._height = 0
        self._line_width = 0
        self._border_width = 0
        self._bitmap = b""
        self._bitmap2 = b""
        self._bpp = 0
        self._bpp2 = 0
        self._skip = False
        self._unknown_end = b""
        if content_data is not None:
            # if self.parent().kind() == "polygon" and type_ in (0x1A, 0x1D):
            #     # # if self.parent().kind() == "point" and type_ == 0x30 and (subtype in (0x03, 0x04)):
            #     # if self.parent().kind() == "point" and type_ == 0x16 and subtype == 0x16:
            #     # if self.parent().kind() == "point" and type_ == 0x2F and subtype == 0x18:
            #     # if self.parent().kind() == "line" and type_ == 0x20:
            #     print(f"Raw data: {content_data.hex()}")
            #     self.decode(content_data)
            # # elif self.parent().kind() == "point" and type_ == 0x0B:
            # #     print(f"Raw data: {content_data.hex()}")
            # #     self.decode(content_data)
            # else:
            #     self._skip = True
            self.decode(content_data)

    def parent(self) -> Collection:
        return self._parent

    def header(self) -> Header:
        return self.parent().parent().header()

    @property
    def orig_offset(self) -> int:
        return self._orig_offset

    @orig_offset.setter
    def orig_offset(self, value: int) -> None:
        self._orig_offset = value

    def type(self) -> int:
        return self._type

    def subtype(self) -> int:
        return self._subtype

    def decode(self, _content_data: bytes) -> None:
        pass

    def data_as_binary(self) -> bytes:
        return b""

    def write_str(self) -> str:
        return ""

    def as_diffvalue(self) -> str:
        return self.data_as_binary().hex()

    def get_rgb_triplets(self, data: bytes, numcolors: int | None = None) -> list[tuple[int, int, int] | None]:
        # @todo: sometimes wrong numcolors
        if (numcolors is None) or (len(data) // 3 < numcolors and len(data) % 6 == 0):
            numcolors = len(data) // 3
            print(f"WARNING: @fixme wrong numcolors {numcolors}")

        colors = []

        for _ in range(numcolors):
            if len(data) < 3:
                msg = f"WARNING: Insufficient data for RGB triplets: {data} | len: {len(data)}"
                print(msg)
                return colors
            rgb = struct.unpack("<BBB", data[:3])
            colors.append(rgb)
            data = data[3:]
        return colors

    def store_rgb_triplets(self, colors: list[tuple[int, int, int] | None]) -> bytes:
        ret = b""
        for rgb in colors:
            if rgb is None:
                continue
            ret += struct.pack("<BBB", *rgb)
        return ret

    def decode_strings(self, data: bytes) -> tuple[list[tuple[int, str]], int]:
        if not data:
            return [], 0

        original_length = len(data)
        result = []
        buf = bytearray(data)

        if len(buf) == 0:
            return [], 0

        length = buf.pop(0)
        multiplier = 1  # 1 for ASCII, 2 for Unicode

        if length % 2 == 0:
            if len(buf) == 0:
                return [], 1
            highbyte = buf.pop(0)
            length += highbyte << 8
            multiplier = 2

        length -= multiplier

        while len(buf) > 0 and length > 0:
            if len(buf) == 0:
                break
            lang = buf.pop(0)
            length -= multiplier * 2

            text = bytearray()
            while len(buf) > 0 and length > 0:
                c = buf.pop(0)
                length -= multiplier * 2
                if c == 0:
                    break
                text.append(c)

            codepage = None
            try:
                codepage = self.header().codepage()
                utf8_text = text.decode(f"cp{codepage}", errors="strict")
            except UnicodeDecodeError:
                try:
                    utf8_text = text.decode(f"cp{codepage}", errors="replace")
                    print(f"WARNING: Invalid characters in language {lang}, codepage {codepage}")
                except Exception:
                    utf8_text = text.decode("latin1", errors="replace")

            result.append((lang, utf8_text))

        bytes_consumed = original_length - len(buf)

        return result, bytes_consumed

    def store_strings(self, strings: list[tuple[int, str]]) -> bytes:
        ret = b""
        for _id1, s in strings:
            encoded = s.encode("cp" + str(self.header().codepage()), errors="replace")
            ret += struct.pack("<B", len(encoded)) + encoded
        return ret

    def unknown_data_as_string(self, data: bytes, description: str) -> str:
        if len(data) == 0 or not data:
            return ""

        print(
            f"WARNING: Unknown left bytes - {description} (kind: {self.parent().kind()}, type: {self._type}, subtype: {self._subtype}) {data.hex()} | {len(data)}"
        )
        return f"; {description}:\n" + TypDecode.hexdump(data) + "\n"

    def customcolors_as_string(self, customcolors: list[tuple[int, int, int] | None]) -> str:
        ret = ""

        if len(customcolors) == 2 and customcolors[0] is not None and customcolors[1] is not None:
            [b1, g1, r1] = customcolors[0]
            [b2, g2, r2] = customcolors[1]
            ret1 = f"{r1:02x}{g1:02x}{b1:02x}"
            ret2 = f"{r2:02x}{g2:02x}{b2:02x}"
            ret = f"CustomColor=DayAndNight\nDaycustomColor:#{ret1.upper()}\nNightcustomColor:#{ret2.upper()}\n"
        else:
            ret = "CustomColor=No\n"

        return ret

    def strings_as_string(self, strings: list[tuple[int, str]]) -> str:
        ret = ""
        for i, [index, s] in enumerate(strings):
            ret += f"String{i + 1}={f'0x{index:02x}'},{s}\n"
        return ret

    def fontsize_as_string(self, fontsize: int) -> str:
        ret = ""
        if fontsize == 0:
            ret = "ExtendedLabels=Y\nFontStyle=Default\n"
        elif fontsize == 1:
            ret = "ExtendedLabels=Y\nFontStyle=NoLabel (invisible)\n"
        elif fontsize == 2:
            ret = "ExtendedLabels=Y\nFontStyle=SmallFont\n"
        elif fontsize == 3:
            ret = "ExtendedLabels=Y\nFontStyle=NormalFont\n"
        elif fontsize == 4:
            ret = "ExtendedLabels=Y\nFontStyle=LargeFont\n"
        else:
            ret = "ExtendedLabels=N\n"

        return ret

    def bitmap_as_string(
        self, bitmap: bytes | None, width: int, height: int, colors: list[tuple[int, int, int] | None], bpp: int | None = None, prefix: str = ""
    ) -> str:
        xmp_chars = "!#%?$*=1234567890.+@&-;:>,<[]{}|^~!/"
        kind = self.parent().kind()

        def _assign_color_name(color_number: int, rgb: tuple[int, int, int] | None, ref_names: list[str | None], is_transparent: bool = False) -> str:
            # Return existing name if already assigned
            if color_number < len(ref_names):
                cn = ref_names[color_number]
                if cn is not None:
                    return cn

            # Extend the list if needed
            while len(ref_names) <= color_number:
                ref_names.append(None)

            # Assign color name
            if is_transparent or rgb is None:
                name = " "  # Space for transparent/background
            elif color_number < len(xmp_chars):
                name = xmp_chars[color_number]
            else:
                # Fallback to two-character names if we run out of single chars
                name = f"{color_number:02d}"

            ref_names[color_number] = name
            return name

        if bpp is None:
            bpp = 1

        ret = ""

        transparent_color_index = -1
        # Common heuristics for transparent color detection or len(colors)
        if len(colors) > 0 and colors[0] is None:
            transparent_color_index = 0
            print("Auto-detected transparent color: index 0 (None in palette)")

        # bytes per line
        w_bytes = (width * bpp + 7) // 8

        color_names = []
        pixel_rows = []

        if bitmap is not None:
            bmap_offset = 0
            for ln in range(height):
                row_colors = []

                if bmap_offset + w_bytes <= len(bitmap):
                    line = bitmap[bmap_offset : bmap_offset + w_bytes]
                    bmap_offset += w_bytes
                else:
                    print("WARNING: Not enough data: we require more minerals!")
                    line = bitmap[bmap_offset:]
                    line += b"\x00" * (w_bytes - len(line))
                    bmap_offset = len(bitmap)

                bit_string = "".join(f"{byte:08b}"[::-1] for byte in line)
                if kind in ("polygon", "line"):
                    bit_string = bit_string.translate(str.maketrans("01", "10"))

                # Process each pixel
                bit_offset = 0
                for x in range(width):
                    if bit_offset + bpp <= len(bit_string):
                        part_bits = bit_string[bit_offset : bit_offset + bpp]
                        bit_offset += bpp
                    else:
                        part_bits = "0" * bpp
                        bit_offset += bpp

                    # Convert bit string to color number
                    color_number = int(part_bits[::-1], 2) if part_bits else 0
                    row_colors.append(color_number)

                    # Handle out-of-bounds color indices
                    if color_number >= len(colors):
                        # print(f"Warning: color_number {color_number} >= colors length {len(colors)} at pixel ({x},{ln})") # maybe has transparancy
                        # Extend colors array with None values
                        while len(colors) <= color_number:
                            colors.append(None)

                    # Assign color name, marking transparency if needed
                    is_transparent = (color_number == transparent_color_index) or (colors[color_number] is None)
                    _assign_color_name(color_number, colors[color_number], color_names, is_transparent)

                pixel_rows.append(row_colors)

        actual_colors = sum(1 for color in colors if color is not None)
        total_colors = len(colors)

        # print(f"Colors: total={total_colors}, actual={actual_colors} | ALL={colors}")

        # Generate XPM header
        lpp = 1  # Number of letters to represent a pixel
        colormode = f"{'  Colormode=16' if total_colors > actual_colors and kind == 'point' else ''}"
        if kind == "point":
            prefix = "Day"
        ret += f'{prefix}Xpm="{width} {height} {total_colors} {lpp}"{colormode}\n'

        # Generate color definitions
        for i, color in enumerate(colors):
            is_transparent = (i == transparent_color_index) or (color is None)
            color_char = _assign_color_name(i, color, color_names, is_transparent)

            if color is not None and not is_transparent:
                b, g, r = color
                rgb = f"{r:02x}{g:02x}{b:02x}"
                color_def = f'"{color_char} c #{rgb.upper()}"\n'
            else:
                color_def = f'"{color_char} c none"\n'  # Transparent

            ret += color_def

        # Generate pixel data
        for ln, row in enumerate(pixel_rows):
            line_start = '"'
            for pixel_color in row:
                if pixel_color < len(color_names) and color_names[pixel_color] is not None:
                    line_start += color_names[pixel_color]
                else:
                    line_start += " "  # Fallback character
                    print(f"Warning: using fallback character at pixel row {ln}")
            size_comment = ""
            for i in range(1, width + 1):
                size_comment += str(i % 10)
            if ln == len(pixel_rows) - 1:  # Last line
                line_start += f'"\n;{size_comment}\n'
            else:
                line_start += '"\n'

            ret += line_start

        return ret


class PolyPlaceholder(Element):
    def __init__(self, parent: Collection, type_: int, subtype: int) -> None:
        super().__init__(parent, type_, subtype, None)
        self._draworder = 0

    def draworder(self, new: int | None = None) -> int:
        if new is not None:
            self._draworder = new
        return self._draworder

    def as_diffvalue(self) -> str:
        return f"{self.type()}/{self.subtype()}/{self.draworder()}"


class Polygon(Element):
    def __init__(self, parent: Collection, type_: int, subtype: int, content_data: bytes) -> None:
        super().__init__(parent, type_, subtype, content_data)

    def colortype_info(self, ctype: int, field: str) -> int | dict | None:
        colortypes = {
            0x06: {"numcolors": 1, "commoncolors": [0], "bitmap": False, "name": "~HTML~POLYGON_COLORTYPE_06~~"},
            0x07: {"numcolors": 2, "daycolors": [0], "nightcolors": [1], "bitmap": False, "name": "~HTML~POLYGON_COLORTYPE_07~~"},
            0x08: {"numcolors": 2, "commoncolors": [0, 1], "bitmap": True, "name": "~HTML~POLYGON_COLORTYPE_08~~"},
            0x09: {"numcolors": 4, "daycolors": [0, 1], "nightcolors": [2, 3], "bitmap": True, "name": "~HTML~POLYGON_COLORTYPE_09~~"},
            0x0B: {
                "numcolors": 3,
                "daycolors": [0],
                "nightcolors": [1, 2],
                "bitmap": True,
                "name": "~HTML~POLYGON_COLORTYPE_0B~~",
            },  # transparent during the day
            0x0D: {"numcolors": 3, "daycolors": [0, 1], "nightcolors": [2], "bitmap": True, "name": "~HTML~POLYGON_COLORTYPE_0D~~"},
            0x0E: {"numcolors": 1, "commoncolors": [0], "bitmap": 1, "name": "~HTML~POLYGON_COLORTYPE_0E~~"},  # transparent
            0x0F: {"numcolors": 2, "daycolors": [0], "nightcolors": [1], "bitmap": True, "name": "~HTML~POLYGON_COLORTYPE_0F~~"},
        }
        if isinstance(ctype, str):
            try:
                ctype = int(ctype)
            except ValueError:
                print(f"WARNING: Invalid colortype string: {ctype}")
                # return colortypes[0x06][field]
                return None

        if ctype not in colortypes:
            print(f"WARNING: Unknown polygon color type: {ctype}, using defaults")
            return colortypes[0x06][field]

        return colortypes[ctype][field] if field else colortypes[ctype]

    def decode(self, content_data: bytes) -> None:
        self._has_l18n = False
        self._color_type = 0
        self._colors = []
        self._bitmap = b""
        self._strings = []
        self._more_info = None
        self._customcolors = []
        self._fontsize = -1
        tmp = content_data
        if not tmp:
            return

        (flags1,) = struct.unpack("<B", tmp[:1])
        tmp = tmp[1:]
        self._color_type = flags1 & 0x0F  # 4-1b
        self._has_l18n = bool(flags1 & 0x10)  # 5b
        self._has_more_info = bool(flags1 & 0x20)  # 6b

        numcolors = self.colortype_info(self._color_type, "numcolors")
        if not isinstance(numcolors, int) or numcolors is None:
            numcolors = 1
        self._colors = self.get_rgb_triplets(tmp, numcolors)
        tmp = tmp[numcolors * 3 :]
        if self.colortype_info(self._color_type, "bitmap"):
            # if self._color_type in colortypes and "bitmap" in colortypes[self._color_type]:
            self._bitmap = tmp[:128]
            tmp = tmp[128:]
        else:
            self._bitmap = b""

        if self._has_l18n:
            self._strings, consumed = self.decode_strings(tmp)
            tmp = tmp[consumed:]
        if self._has_more_info:
            (self._more_info,) = struct.unpack("<B", tmp[:1])
            tmp = tmp[1:]
            self._fontsize = self._more_info & 0x07
            if len(tmp) >= 3:
                numcolors = TypDecode.checkcustomcolor(self._more_info)
                self._customcolors = self.get_rgb_triplets(tmp, numcolors)
                tmp = tmp[len(self._customcolors) * 3 :]
        self._unknown_end = tmp

    def data_as_binary(self) -> bytes:
        ret = b""
        ret += struct.pack("<B", self._color_type | (0x10 if self._has_l18n else 0x00) | (0x20 if self._more_info else 0x00))
        ret += self.store_rgb_triplets(self._colors)
        ret += self._bitmap
        ret += self.store_strings(self._strings)
        if self._more_info:
            ret += struct.pack("<B", self._more_info)
            ret += self.store_rgb_triplets(self._customcolors)
        ret += self._unknown_end
        return ret

    def write_str(self) -> str:
        if self._skip:
            return ""

        ret = f"[_{self.parent().kind()}]\n"
        type_format = f"{self._type:03x}{self._subtype:02x}" if self._subtype != 0 or self._type >= 256 else f"{self._type:02x}"
        ret += f"Type=0x{type_format}\n"
        if self._has_l18n:
            ret += self.strings_as_string(self._strings)
        ret += self.fontsize_as_string(self._fontsize)
        ret += self.customcolors_as_string(self._customcolors)
        has_bitmap = self.colortype_info(self._color_type, "bitmap")
        ret += self.bitmap_as_string(self._bitmap if has_bitmap else None, 32, 32, self._colors, 1, "")
        ret += self.unknown_data_as_string(self._unknown_end, f"unknown {self.parent().kind()} data")
        ret += "[end]\n\n\n"
        return ret


class Line(Element):
    line_colortypes: ClassVar[dict] = {
        0x00: {"numcolors": 2, "commoncolors": [0, 1], "name": "with border"},
        0x01: {"numcolors": 4, "daycolors": [0, 1], "nightcolors": [2, 3], "name": "day/night with border"},
        # 0x02: @todo
        0x03: {"numcolors": 3, "daycolors": [0], "nightcolors": [1, 2], "name": "day/night"},
        # 0x04: @todo
        0x05: {"numcolors": 3, "daycolors": [0, 1], "nightcolors": [2], "borderless": True, "name": "borderless day/night"},
        0x06: {"numcolors": 1, "commoncolors": [0], "borderless": True, "name": "borderless single color"},
        0x07: {"numcolors": 2, "daycolors": [0], "nightcolors": [1], "borderless": True, "name": "borderless day/night"},
    }

    def __init__(self, parent: Collection, type_: int, subtype: int, content_data: bytes) -> None:
        super().__init__(parent, type_, subtype, content_data)

    @property
    def l18n(self) -> bool:
        return self._has_l18n

    def colortype_info(self, ctype: int, field: str) -> dict | int | None:
        if ctype not in self.line_colortypes:
            print(f"WARNING: Unknown line color type: {ctype}, using defaults")
            # defaults = {"bitmap": False, "numcolors": 2}
            # return defaults[field] if field else defaults
            return None
        if field:
            defaults = {"bitmap": False, "numcolors": 2}
            return self.line_colortypes[ctype].get(field, defaults.get(field, None))

        return self.line_colortypes[ctype]

    def height(self, new: int | None = None) -> int:
        if new is not None:
            if new < 0 or new > 31:
                msg = f"Height out of range: {new}"
                raise ValueError(msg)
            self._height = new
        return self._height

    def orientation(self, new: bool | None = None) -> bool:
        if new is not None:
            self._orientation = new
        return self._orientation

    def decode(self, content_data: bytes) -> None:
        self._has_l18n = False
        self._orientation = False
        self._height = 0
        self._color_type = 0
        self._bitmapped = False
        self._line_width = 0
        self._border_width = 0
        self._more_info = None
        self._colors = []
        self._bitmap = b""
        self._strings = []
        self._customcolors = []
        self._fontsize = -1
        tmp = content_data

        if len(tmp) < 2:
            return

        flags1, flags2 = struct.unpack("<BB", tmp[:2])
        tmp = tmp[2:]
        self._color_type = flags1 & 0x07
        self._height = flags1 >> 3
        self._has_l18n = bool(flags2 & 0x01)  # 1b
        self._orientation = bool(flags2 & 0x02)  # 2b
        self._has_more_info = bool(flags2 & 0x04)  # 3b

        numcolors = self.colortype_info(self._color_type, "numcolors")
        if not isinstance(numcolors, int) or numcolors is None:
            numcolors = 1
        self._colors = self.get_rgb_triplets(tmp, numcolors)
        tmp = tmp[numcolors * 3 :]
        if self._height == 0:
            self._bitmap = b""
            if self.colortype_info(self._color_type, "borderless"):
                if len(tmp) < 1:
                    msg = "Insufficient data for line width"
                    raise ValueError(msg)
                (lsize,) = struct.unpack("<B", tmp[:1])
                tmp = tmp[1:]
                totalsize = lsize
            else:
                if len(tmp) < 2:
                    msg = "Insufficient data for line and border width"
                    raise ValueError(msg)
                lsize, totalsize = struct.unpack("<BB", tmp[:2])
                tmp = tmp[2:]
            self._line_width = lsize
            self._border_width = (totalsize - lsize) // 2
        else:
            self._bitmapped = True
            bitmap_size = 4 * self._height
            if len(tmp) < bitmap_size:
                msg = "Insufficient data for bitmap"
                raise ValueError(msg)
            self._bitmap = tmp[:bitmap_size]
            tmp = tmp[bitmap_size:]

        if self._has_l18n:
            self._strings, consumed = self.decode_strings(tmp)
            tmp = tmp[consumed:]
        if self._has_more_info:
            (self._more_info,) = struct.unpack("<B", tmp[:1])
            tmp = tmp[1:]
            self._fontsize = self._more_info & 0x07
            if len(tmp) >= 3:
                numcolors = TypDecode.checkcustomcolor(self._more_info)
                self._customcolors = self.get_rgb_triplets(tmp, numcolors)
                tmp = tmp[len(self._customcolors) * 3 :]
        self._unknown_end = tmp

    def data_as_binary(self) -> bytes:
        ret = b""
        ret += struct.pack("<B", self._color_type | (self._height << 3))
        ret += struct.pack("<B", (0x01 if self._has_l18n else 0x00) | (0x02 if self._orientation else 0x00) | (0x04 if self._has_more_info else 0x00) | 0x00)
        ret += self.store_rgb_triplets(self._colors)
        if self._height == 0:
            if self.colortype_info(self._color_type, "borderless"):
                ret += struct.pack("<B", self._line_width)
            else:
                ret += struct.pack("<BB", self._line_width, self._line_width + 2 * self._border_width)
        else:
            ret += self._bitmap
        ret += self.store_strings(self._strings)
        if self._more_info:
            ret += struct.pack("<B", self._more_info)
            ret += self.store_rgb_triplets(self._customcolors)
        ret += self._unknown_end
        return ret

    def write_str(self) -> str:
        if self._skip:
            return ""

        ret = f"[_{self.parent().kind()}]\n"
        type_format = f"{self._type:03x}{self._subtype:02x}" if self._subtype != 0 or self._type >= 256 else f"{self._type:02x}"
        ret += f"Type=0x{type_format}\n"
        if self._has_l18n:
            ret += self.strings_as_string(self._strings)
        ret += f"UseOrientation={'N' if self._orientation else 'Y'}\n"
        ret += self.fontsize_as_string(self._fontsize)
        ret += self.customcolors_as_string(self._customcolors)
        if self._height == 0:
            ret += self.bitmap_as_string(None, 0, 0, self._colors, 1, "")
            if self.colortype_info(self._color_type, "borderless"):
                ret += f"LineWidth={self._line_width}\n"
            else:
                ret += f"LineWidth={self._line_width}\n"
                ret += f"BorderWidth={self._border_width}\n"
        else:
            ret += self.bitmap_as_string(self._bitmap, 32, self._height, self._colors, 1, "")
        ret += self.unknown_data_as_string(self._unknown_end, f"unknown {self.parent().kind()} data")
        ret += "[end]\n\n\n"
        return ret


class Point(Element):
    def __init__(self, parent: Collection, type_: int, subtype: int, content_data: bytes) -> None:
        super().__init__(parent, type_, subtype, content_data)

    # self._bitmap = b""
    # self._bitmap2 = b""

    def height(self, new: int | None = None) -> int:
        if new is not None:
            if new < 0 or new > 255:
                msg = f"Height out of range: {new}"
                raise ValueError(msg)
            self._height = new
        return self._height

    def width(self, new: int | None = None) -> int:
        if new is not None:
            if new < 0 or new > 255:
                msg = f"Width out of range: {new}"
                raise ValueError(msg)
            self._width = new
        return self._width

    def xflags(self) -> int:
        return self._x3

    def xflags2(self) -> int:
        return self._x3b

    def bpp(self) -> int:
        return self._bpp

    def bpp2(self) -> int:
        return self._bpp2

    def bitmap2(self, new: bytes | None = None) -> bytes:
        if new is not None:
            self._bitmap2 = new if new else b""
        return self._bitmap2

    X3_FLAG_00 = 0x00
    X3_FLAG_10 = 0x10
    X3_FLAG_20 = 0x20

    def bpp_and_width_in_bytes(self, numcolors: int, w_pixels: int, x3_flag: int) -> tuple[int, int]:
        bpp = 0
        if x3_flag == self.X3_FLAG_00:
            bpp_dict = {0: 16, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4}
            bpp_dict.update(dict.fromkeys(range(6, 16), 4))
            bpp_dict.update(dict.fromkeys(range(16, 33), 8))
            bpp_dict.update(dict.fromkeys(range(33, 256), 8))
            bpp = bpp_dict.get(numcolors, 8)
        elif x3_flag == self.X3_FLAG_10:
            bpp_dict = {0: 1}
            bpp_dict.update(dict.fromkeys(range(1, 3), 2))
            bpp_dict.update(dict.fromkeys(range(3, 15), 4))
            bpp_dict.update(dict.fromkeys(range(15, 256), 8))
            bpp = bpp_dict.get(numcolors, 8)
        elif x3_flag == self.X3_FLAG_20:
            bpp_dict = {0: 16, 1: 1}
            bpp_dict.update(dict.fromkeys(range(2, 4), 2))
            bpp_dict.update(dict.fromkeys(range(4, 16), 4))
            bpp_dict.update(dict.fromkeys(range(16, 256), 8))
            bpp = bpp_dict.get(numcolors, 8)
        else:
            msg = f"Unknown image flag: {x3_flag}"
            raise ValueError(msg)
        w_pixels_bytes = (w_pixels * bpp) // 8
        if (w_pixels * bpp) % 8 != 0:
            w_pixels_bytes += 1
        if bpp < 0:
            w_pixels_bytes = 0
        return bpp, w_pixels_bytes

    def decode(self, content_data: bytes) -> None:
        self._has_l18n = False
        self._width = 0
        self._height = 0
        self._more_info = None
        self._colors = []
        self._bitmap = b""
        self._colors2 = []
        self._bitmap2 = b""
        self._customcolors = []
        self._strings = []
        self._x3 = 0
        self._x3b = 0
        self._bpp = 0
        self._bpp2 = 0
        self._fontsize = -1
        tmp = content_data

        if not tmp:
            return

        flags1, width, height, colors, x3 = struct.unpack("<BBBBB", tmp[:5])
        tmp = tmp[5:]
        self._has_l18n = bool(flags1 & 0x04)  # 3b
        self._has_more_info = bool(flags1 & 0x08)  # 4b

        flags1 &= ~0x08  # invertva 4b
        self._width = width
        self._height = height
        self._x3 = x3
        self._bpp, w_bytes = self.bpp_and_width_in_bytes(colors, width, x3)
        if x3 in (0x00, 0x20) and colors == 0 and self._bpp >= 16:
            colors = width * height
        self._colors = self.get_rgb_triplets(tmp, colors)
        tmp = tmp[colors * 3 :]
        if self._bpp >= 16:
            self._bitmap = b""
            for i in range(colors):
                self._bitmap += struct.pack("<H", i)
        else:
            bitmap_size = height * w_bytes
            if len(tmp) < bitmap_size:
                msg = "Insufficient data for bitmap"
                raise ValueError(msg)
            self._bitmap = tmp[:bitmap_size]
            tmp = tmp[bitmap_size:]

        if flags1 == 0x02:  # 2b
            colors2, x3b = struct.unpack("<BB", tmp[:2])
            tmp = tmp[2:]
            self._x3b = x3b
            self._colors2 = self.get_rgb_triplets(tmp, colors2)
            tmp = tmp[colors2 * 3 :]
            self._bpp2, w_bytes2 = self.bpp_and_width_in_bytes(colors2, width, x3b)
            if flags1 == 0x01:  # 1b: has_bitmap = True
                bitmap_size2 = height * w_bytes2
                if len(tmp) < bitmap_size2:
                    msg = "Insufficient data for second bitmap"
                    raise ValueError(msg)
                self._bitmap2 = tmp[:bitmap_size2]
                tmp = tmp[bitmap_size2:]
            else:
                self._bitmap2 = b""

        if self._has_l18n:
            self._strings, consumed = self.decode_strings(tmp)
            tmp = tmp[consumed:]
        if self._has_more_info:
            (self._more_info,) = struct.unpack("<B", tmp[:1])
            tmp = tmp[1:]
            self._fontsize = self._more_info & 0x07
            if len(tmp) >= 3:
                numcolors = TypDecode.checkcustomcolor(self._more_info)
                self._customcolors = self.get_rgb_triplets(tmp, numcolors)
                tmp = tmp[len(self._customcolors) * 3 :]

        self._unknown_end = tmp

    def data_as_binary(self) -> bytes:
        ret = b""
        color_mode = 0x01 if self._bitmap else 0x00
        if self._bitmap2:
            color_mode |= 0x02
        elif self._colors2:
            color_mode = 0x02
        ret += struct.pack(
            "<BBBBB",
            color_mode | (0x04 if self._has_l18n else 0x00) | (0x08 if self._more_info else 0x00) | self._has_more_info,
            self._width,
            self._height,
            0 if self._bpp >= 16 else len(self._colors),
            self._x3,
        )
        ret += self.store_rgb_triplets(self._colors)
        if self._bpp < 16:
            ret += self._bitmap
        if self._colors2:
            ret += struct.pack("<BB", len(self._colors2), self._x3b)
            ret += self.store_rgb_triplets(self._colors2)
        if self._bitmap2:
            ret += self._bitmap2
        ret += self.store_strings(self._strings)
        if self._more_info:
            ret += struct.pack("<B", self._more_info)
            ret += self.store_rgb_triplets(self._customcolors)
        ret += self._unknown_end
        return ret

    def write_str(self) -> str:
        if self._skip:
            return ""

        ret = f"[_{self.parent().kind()}]\n"
        type_format = f"{self._type:03x}{self._subtype:02x}" if self._subtype != 0 or self._type >= 256 else f"{self._type:02x}"
        ret += f"Type=0x{type_format}\n"
        if self._has_l18n:
            ret += self.strings_as_string(self._strings)
        ret += self.fontsize_as_string(self._fontsize)
        ret += self.customcolors_as_string(self._customcolors)
        if self._bitmap2:
            ret += self.bitmap_as_string(self._bitmap, self._width, self._height, self._colors, self._bpp, "Day")
            ret += self.bitmap_as_string(self._bitmap2, self._width, self._height, self._colors2, self._bpp2, "Night")
        else:
            ret += self.bitmap_as_string(self._bitmap, self._width, self._height, self._colors, self._bpp, "")
        ret += self.unknown_data_as_string(self._unknown_end, f"unknown {self.parent().kind()} data")
        ret += "[end]\n\n\n"
        return ret


class NT1Point(Point):
    # def __init__(self, parent: Collection, type_: int, subtype: int, content_data: bytes) -> None:
    #     super().__init__(parent, type_, subtype, content_data)

    def decode(self, content_data: bytes) -> None:
        self._first_prefix = b""
        self._first_thumbnail = None
        self._types_prefix = b""
        self._second_thumbnail = None

        self._first_prefix = content_data[:3]
        ptype = struct.unpack("<B", self._first_prefix[2:3])[0]
        tmp = content_data[3:]
        self._first_thumbnail = Point(self.parent(), self._type, self._subtype, tmp)
        self._first_thumbnail.decode(tmp)
        tmp = self._first_thumbnail._unknown_end
        self._first_thumbnail._unknown_end = b""
        self._unknown_end = tmp
        if tmp:
            if ptype == 0x02:
                self._types_prefix = tmp[:1]
                tmp = tmp[1:]
            elif ptype in (0x04, 0x05, 0x09, 0x0A, 0x12, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2F, 0x6C):
                self._types_prefix = tmp[:2]
                tmp = tmp[2:]
            else:
                self._types_prefix = b""
            self._unknown_end = tmp
            if tmp:
                self._second_thumbnail = Point(self.parent(), self._type, self._subtype, tmp)
                self._second_thumbnail.decode(tmp)
                self._unknown_end = self._second_thumbnail._unknown_end
                self._second_thumbnail._unknown_end = b""

    def data_as_binary(self) -> bytes:
        ret = self._first_prefix
        if self._first_thumbnail:
            ret += self._first_thumbnail.data_as_binary()
        ret += self._types_prefix
        if self._second_thumbnail:
            ret += self._second_thumbnail.data_as_binary()
        ret += self._unknown_end
        return ret

    def write_str(self) -> str:
        if self._skip:
            return ""

        ret = f"[_{self.parent().kind()}]\n"
        ret += f"; First prefix: {TypDecode.hexdump(self._first_prefix)}"
        ret += "; First POI:\n"
        if self._first_thumbnail:
            ret += self._first_thumbnail.write_str()
        ret += f"; Second prefix: {TypDecode.hexdump(self._types_prefix)}"
        if self._second_thumbnail:
            ret += "; Second POI:\n"
            ret += self._second_thumbnail.write_str()
        ret += self.unknown_data_as_string(self._unknown_end, f"unknown {self.parent().kind()} data")
        return ret


class DrawOrder:
    def __init__(self, parent: GarminTYP, content_data: bytes) -> None:
        self._parent = parent
        self._raw_original = content_data
        self._parts: list[tuple[int, int]] = []

        while content_data:
            if len(content_data) < 5:
                break
            type_, subtype_mask = struct.unpack("=BL", content_data[:5])
            self._parts.append((type_, subtype_mask))
            content_data = content_data[5:]

        header_uses_bitmap = parent.header().format() in ("NT", "NT2")

        if not header_uses_bitmap:
            for type_, subtype_mask in self._parts:
                if subtype_mask != 0:
                    highbyte, foo1, subtype = struct.unpack("=BBH", struct.pack("=L", subtype_mask))
                    check_type = type_ + (highbyte << 8)
                    if foo1 != 0 or check_type > 0x011F or subtype > 0x001F:
                        header_uses_bitmap = True
                        break

        if parent.header().format() in ("NT", "NT2") and not header_uses_bitmap:
            parent.error("Header is in NT format, but DrawOrder is in old format.")
        elif parent.header().format() == "OLD" and header_uses_bitmap:
            parent.error("Header is in OLD format, but DrawOrder uses short types with subtype bitmap.")

        lvl = self.min_level()
        for type_, subtype_mask in self._parts:
            if type_ == 0 and subtype_mask == 0:
                lvl += 1
            elif subtype_mask == 0:
                ph = PolyPlaceholder(self.parent().polyplaceholders(), type_, 0)
                ph.draworder(lvl)
                self.parent().polyplaceholders().add_element(ph, f"{type_}_0")
            elif header_uses_bitmap:
                mask_bytes = struct.pack("<L", subtype_mask)
                for start in range(0x20):
                    byte_idx = start // 8
                    bit_idx = start % 8
                    if byte_idx < len(mask_bytes) and (mask_bytes[byte_idx] >> bit_idx) & 1:
                        combined_type = type_ | 0x100
                        ph = PolyPlaceholder(
                            self.parent().polyplaceholders(),
                            combined_type,
                            start,
                        )
                        ph.draworder(lvl)
                        self.parent().polyplaceholders().add_element(ph, f"{combined_type}_{start}")
            else:
                # old format, subtype_mask unpacking
                highbyte, foo1, subtype = struct.unpack("=BBH", struct.pack("=L", subtype_mask))
                if foo1 != 0:
                    parent.error(
                        f"TYP contains old-format draworder with unknown content: type=0x{type_:02x}, subtype=0x{subtype:02x}, unknown data={foo1:02x}"
                    )

                final_type = type_ | (highbyte << 8)
                ph = PolyPlaceholder(self.parent().polyplaceholders(), final_type, subtype)
                ph.draworder(lvl)
                self.parent().polyplaceholders().add_element(ph, f"{final_type}_{subtype}")

    def parent(self) -> GarminTYP:
        return self._parent

    def min_level(self) -> int:
        return 1

    def max_level(self) -> int:
        return max(
            (elem.draworder() for elem in self.parent().polyplaceholders().iterate()),
            default=0,
        )

    def all_elements_for_level(self, level: int) -> list[Any]:
        all_polygons = self.parent().polygons().iterate() if self.parent().polygons() else []
        all_placeholders = self.parent().polyplaceholders().iterate()
        valid_placeholders = [ph for ph in all_placeholders if any(poly.type() == ph.type() and poly.subtype() == ph.subtype() for poly in all_polygons)]
        ret = [e for e in valid_placeholders + all_polygons if hasattr(e, "draworder") and e.draworder() == level]
        return sorted(ret, key=lambda e: (e.type() & 0xFF, e.subtype()))

    def length(self) -> int:
        return len(self.as_binary())

    def write_str(self) -> str:
        ret = "[_drawOrder]\n"
        for lvl in range(self.min_level(), self.max_level() + 1):
            for e in self.all_elements_for_level(lvl):
                if e.type() == 0:
                    self.parent().error("Element type for draworder cannot be 0")
                if e.type() >= 0x100:
                    str1 = f"{(e.type() << 8) + e.subtype():05x},{lvl}"
                    ret += f"Type=0x{str1}\n"
                else:
                    str1 = f"{e.type():02x},{lvl}"
                    ret += f"Type=0x{str1}\n"
        ret += "[end]\n\n\n"
        return ret

    def as_binary(self) -> bytes:
        ret = b""
        used = {}
        previous_level_is_empty = True
        for lvl in range(self.min_level(), self.max_level() + 1):
            used_here = {}
            elements = self.all_elements_for_level(lvl)
            if elements:
                if not previous_level_is_empty:
                    ret += struct.pack("<BII", 0, 0, 0)
                previous_level_is_empty = False
            subtypes_by_type = {}
            for e in elements:
                if e.type() == 0:
                    self.parent().error("Element type for draworder cannot be 0")
                key = f"{e.type()}/{e.subtype()}"
                used[key] = used.get(key, 0) + 1
                used_here[key] = used_here.get(key, 0) + 1
                if used[key] > 1:
                    self.parent().error(f"TYP contains duplicit placeholder of type 0x{e.type():03x}/0x{e.subtype():02x}!")
                if e.type() < 0x100:
                    ret += struct.pack("<BI", e.type(), 0)
                else:
                    if self.parent().header().format() in ("NT", "NT2"):
                        if e.type() > 0x1FF:
                            self.parent().error(f"TYP contains draworder with too high element type: 0x{e.type():02x}, ignoring")
                            continue
                        if e.subtype() > 0x1F:
                            self.parent().error(f"TYP contains draworder with too high element subtype: 0x{e.subtype():02x}, ignoring")
                            continue
                    else:
                        if e.type() > 0xFFFF:
                            self.parent().error(f"TYP contains draworder with too high element type: 0x{e.type():02x}, ignoring")
                            continue
                        if e.subtype() > 0xFFFFF:
                            self.parent().error(f"TYP contains draworder with too high element subtype: 0x{e.subtype():02x}, ignoring")
                            continue
                    if e.type() not in subtypes_by_type:
                        subtypes_by_type[e.type()] = {}
                    subtypes_by_type[e.type()][e.subtype()] = 1
            for type_ in sorted(subtypes_by_type.keys()):
                sm = subtypes_by_type.get(type_, {})
                if sm:
                    if self.parent().header().format() in ("NT", "NT2"):
                        ret += struct.pack("<B", type_ & 0xFF)
                        bmask = "".join("1" if sm.get(start) else "0" for start in range(0x20))
                        ret += struct.pack("<I", int(bmask, 2))
                    else:
                        for subtype in sorted(sm.keys()):
                            ret += struct.pack("<HBH", type_, 0, subtype)
        return ret


class NTBlocks:
    def __init__(self, parent: GarminTYP) -> None:
        self._parent = parent

    def parent(self) -> GarminTYP:
        return self._parent

    def write_str(self) -> str:
        ret = ""
        hdr = self.parent().header()
        if hdr.nt1:
            ret += f"; NT1 header part:\n; y=0x{hdr.nt1['y']:02x}\n\n"
        if hdr.nt2:
            ret += (
                "; NT2 header part:\n"
                f"; x=0x{hdr.nt2['x']:02x}\n"
                f"; y/z=0x{hdr.nt2['y']:02x}/0x{hdr.nt2['z']:02x}\n"
                f"; u/v=0x{hdr.nt2['u']:02x}/0x{hdr.nt2['v']:02x}\n"
                f"; w=0x{hdr.nt2['w']:02x}\n"
                f"; block 0 length=0x{len(hdr.nt2['block0']):04x}:\n"
                f"; block 1 length=0x{len(hdr.nt2['block1']):04x}:\n"
                f"; block 2 length=0x{len(hdr.nt2['block2']):04x}:\n\n"
            )
        return ret

    def as_binary(self) -> bytes:
        ret = b""
        hdr = self.parent().header()
        if hdr.nt2:
            if hdr.nt2["block0_pos"] > 0:
                ret += hdr.nt2["block0"]
            if hdr.nt2["block1_pos"] > 0:
                ret += hdr.nt2["block1"]
            if hdr.nt2["block2_pos"] > 0:
                ret += hdr.nt2["block2"]
        return ret


def create_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Decrypt Garmin TYP files", epilog="Example: python3 typdecode.py -o ./build/ -n my_map -c config.yaml")

    parser.add_argument("-i", "--input", required=True, help="Input .typ file")
    parser.add_argument("-o", "--output", required=True, help="Output .txt file")

    return parser


def main() -> None:
    """Decompile Garmin TYP files."""
    parser = create_argument_parser()
    args = parser.parse_args()

    if not Path(args.input).is_file():
        print(f"Error: Input file '{args.input}' does not exist.")
        return

    try:
        with Path(args.input).open("rb") as f:
            raw_data = f.read()

        typ = GarminTYP(raw_data)
        typ.write_str(args.output)
    except Exception as e:  # noqa: BLE001
        _exc_type, _exc_obj, exc_tb = sys.exc_info()
        if exc_tb is not None:
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(f"[{fname}:{exc_tb.tb_lineno}] Error: {e}")
        print(traceback.format_exc())


if __name__ == "__main__":
    main()
