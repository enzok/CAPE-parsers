from cape_parsers.CAPE.community.AuroraStealer import extract_config

def test_aurorastealer():
    with open("tests/data/malware/8da8821d410b94a2811ce7ae80e901d7e150ad3420d677b158e45324a6606ac4", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "BuildID": "x64pump",
            "MD5Hash": "f29f33b296b35ec5e7fc3ee784ef68ee",
            "C2": "77.91.85.73",
            "Architecture": "X64",
            "BuildGroup": "x64pump",
            "BuildAccept": "0",
            "Date": "2023-04-06 19",
        }
