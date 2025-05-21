from pathlib import Path

import requests


def handle_test(args):
    sbom_file: Path = args.sbom
    assert sbom_file.exists(), f"{sbom_file} doesn't exists"

    requests.post()

    # curl -X "POST" "${API_BASE_URL}/api/v1/bom" \
    #         -H 'Content-Type: multipart/form-data' \
    #            -H "X-Api-Key: ${API_KEY}" \
    #               -F "autoCreate=true" \
    #                  -F "projectName=${PROJECT_NAME}" \
    #                     -F "projectVersion=latest" \
    #                        -F "isLatest=true" \
    #                           -F "parentUUID=15485c6a-7395-48f8-bcc7-1db3148eb76b" \
    #                              -F "bom=@${BOM_FILE}"
