# Copyright (C) 2026 enzok
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging
import struct

import pefile
import yara

log = logging.getLogger(__name__)

DESCRIPTION = "SandMaskLoader payload dumper."
AUTHOR = "enzok"

yara_rule = """
rule SandMaskLoader
{
    meta:
        description = "SandMaskLoader Payload"
        cape_type = "SandMaskLoader Payload"

    strings:
        $key = { 48 83 EC ?? C7 05 [8] E8 [4] 84 C0 74 }
        $block_1 = { 48 89 5C 24 ?? BB 3C 00 00 00 }
        $block_2 = { B9 10 27 00 00 FF 15 [3] 00 48 83 EB 01 75 }
        $block_3 = { 48 8B 5C 24 ?? 32 C0 48 83 C4 ?? C3 }
        $block_4 = { B9 10 27 00 00 FF 15 [3] 00 32 C0 48 83 C4 ?? C3 }
        $payload = { C7 05 [8] 48 8D 05 [4] C3}

    condition:
        $key and $payload and 3 of ($block*)
}
"""

yara_rules = yara.compile(source=yara_rule)

M64 = (1 << 64) - 1


def yara_scan(raw_data):
    try:
        return yara_rules.match(data=raw_data)
    except Exception as e:
        log.error("Yara scan failed: %s", e)
        return []


def lcg_xor_crypt(buf, key, modulus):
    """LcgXorCryptBuffer both en/decrypts.

        state = key
        b == 0   -> stays 0, and NO rand is consumed (this is why plaintext
                    zero runs survive encryption and keep the keystream aligned)
        ks       = ((rand() % modulus) & 0xFF) ^ (key & 0xFF)
        ks == b  -> b left unchanged (avoids emitting a 0)
        else     -> b ^ ks
        rand: state = 214013*state + 2531011 (mod 2^64); ret (state >> 16) & 0x7FFF
    """
    st = key
    out = bytearray(buf)
    for i, b in enumerate(buf):
        if b == 0:
            continue
        st = (214013 * st + 2531011) & M64
        ks = ((((st >> 16) & 0x7FFF) % modulus) & 0xFF) ^ (key & 0xFF)
        out[i] = ks if ks == b else ks ^ b
    return bytes(out)


def get_hit(hit, name):
    """Fetch the single instance of $<name>, refusing to guess if ambiguous."""
    for item in hit.strings:
        if item.identifier != "$" + name:
            continue

        if len(item.instances) != 1:
            return

        instance = item.instances[0]
        return instance.offset, bytes(instance.matched_data)


def decrypt_payload(filebuf, hit):
    """Locate, slice and decrypt the embedded blob. Returns (payload, key)."""
    key_hit = get_hit(hit, "key")
    payload_hit = get_hit(hit, "payload")

    if not key_hit or not payload_hit:
        log.error("Ambiguous or missing key/payload match")
        return b"", 0

    _, key_match = key_hit
    payload_off, payload_match = payload_hit
    key = struct.unpack_from("<I", key_match, 10)[0]
    size = struct.unpack_from("<I", payload_match, 6)[0]
    disp = struct.unpack_from("<i", payload_match, 13)[0]
    pe = pefile.PE(data=filebuf, fast_load=True)
    blob_rva = pe.get_rva_from_offset(payload_off + 17) + disp
    blob_off = pe.get_offset_from_rva(blob_rva)
    blob = filebuf[blob_off: blob_off + size]
    final_key = key + 255

    return lcg_xor_crypt(blob, final_key, size), final_key


def extract_config(filebuf):
    config = {}

    for hit in yara_scan(filebuf):
        if hit.rule != "SandMaskLoader":
            continue

        try:
            payload, key = decrypt_payload(filebuf, hit)
        except Exception as e:
            log.error("Failed to decrypt payload: %s", e)
            return config

        if payload:
            config["cryptokey"] = f"{key:x}"
            config["cryptokey_type"] = "LCG XOR"
            config["dump_files"] = {"payload": payload}

        break

    return config


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        conf = extract_config(f.read())

    for name, payload in conf.pop("dump_files", {}).items():
        print(f"{name}: {len(payload)} bytes")

    for key, value in conf.items():
        print(f"{key}: {value}")
