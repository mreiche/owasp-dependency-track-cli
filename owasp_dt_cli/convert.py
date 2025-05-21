import json
from pathlib import Path
from typing import cast

from cyclonedx.model.bom import Bom
from cyclonedx.output import make_outputter, BaseOutput, OutputFormat, SchemaVersion
from xml.etree import ElementTree

def handle_convert(args):
    input_file = Path(args.sbom)
    assert input_file.exists()

    with open(input_file) as input_json:

        if input_file.suffix.lower() == ".xml":
            deserialized_bom = cast(Bom, Bom.from_xml(data=ElementTree.fromstring(input_json.read())))
            output_format = OutputFormat.JSON
            suffix = "json"
        else:
            deserialized_bom = Bom.from_json(data=json.loads(input_json.read()))
            output_format = OutputFormat.XML
            suffix = "xml"

    outputter: BaseOutput = make_outputter(bom=deserialized_bom, output_format=output_format, schema_version=SchemaVersion.V1_2)
    outputter.output_to_file(filename=f"{input_file.parent.absolute()}/{input_file.stem}.{suffix}")
