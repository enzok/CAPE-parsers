# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cape_parsers.CAPE.core.Latrodectus import extract_config


def test_latrodectus():
    with open("tests/data/malware/719e19ead52a80b15bf887f3b9a6ab6d50c15d026766db41302c5e4b12949295", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "C2": ["https://piloferstaf.com/test/", "https://ypredoninen.com/test/"],
            "Group name": "Sigma",
            "Campaign ID": 2386938644,
            "Version": "1.8",
            "RC4 key": "XTpawuOlVTpNs6JsxElGCO0gbRa6Gkw7oEmotQWSfM9Qu3j1GYCDs2JETmfatWCI",
        }
