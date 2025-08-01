# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from cape_parsers.CAPE.community.KoiLoader import extract_config

def test_koiloader():
    with open("tests/data/malware/b462e3235c7578450b2b56a8aff875a3d99d22f6970a01db3ba98f7ecb6b01a0", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {"CNCs": ["http://91.202.233.209/hypermetropia.php", "https://admiralpub.ca/wp-content/uploads/2017"]}
