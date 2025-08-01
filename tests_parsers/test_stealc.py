# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cape_parsers.CAPE.community.Stealc import extract_config


def test_stealc():
    with open("tests/data/malware/619751f5ed0a9716318092998f2e4561f27f7f429fe6103406ecf16e33837470", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "CNCs": ["http://95.217.125.57/2f571d994666c8cb.php"],
            "botnet": "5385386367"
        }
