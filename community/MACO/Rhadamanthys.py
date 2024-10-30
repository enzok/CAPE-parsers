import os

from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel
from modules.processing.parsers.CAPE.Rhadamanthys import extract_config


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    parsed_result = MACOModel(family="Rhadamanthys", other=raw_config)
    parsed_result.http = [MACOModel.Http(hostname=raw_config["C2"], usage="c2")]

    return parsed_result


class Rhadamanthys(Extractor):
    author = "kevoreilly"
    family = "Rhadamanthys"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = open(os.path.join(os.path.dirname(__file__).split("/modules", 1)[0], f"data/yara/CAPE/{family}.yar")).read()

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))