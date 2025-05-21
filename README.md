# OWASP Dependency Tracker CLI

### Setup Azure OIDC

- https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc

## API Documentation

- Open https://validator.swagger.io/ with `http://localhost:8081/api/openapi.json`

## Usage

### Convert JSON to XML
```shell
python convert.py sbom.json
```

## API-Key

Setup a user with API key and the following permissions:
- VIEW_VULNERABILITY

### Upload BOM
```shell
export API_KEY="odt_6HHFfo9k_LDYiufseAbTHe1h3CYkwN15wohg6SGAG"
export API_BASE_URL="http://localhost:8081/api"
export PROJECT_NAME="webapp"
export BOM_FILE="test-files/webapp-sbom.xml"
export PROJECT_NAME="iam-gatekeeper"
export BOM_FILE="gatekeeper-sbom.xml"
export PROJECT_NAME="iam-bom"
export BOM_FILE="iam-sbom.xml"
export PROJECT_NAME="dependency-tracker"
export BOM_FILE="test-files/dependency-track-sbom.json"

curl -X "POST" "${API_BASE_URL}/v1/bom" \
     -H 'Content-Type: multipart/form-data' \
     -H "X-Api-Key: ${API_KEY}" \
     -F "autoCreate=true" \
     -F "projectName=${PROJECT_NAME}" \
     -F "projectVersion=latest" \
     -F "isLatest=true" \
     -F "parentUUID=15485c6a-7395-48f8-bcc7-1db3148eb76b" \
     -F "bom=@${BOM_FILE}"

# Es geht wohl auch JSON: -F "bom=@json.json;type=application/json"
```

### Get Projects
```shell
curl -X "GET" "${API_BASE_URL}/v1/projects" \
     -H "X-Api-Key: ${API_KEY}"
```

## SBOM generation

### NPM

```shell
npx --package @cyclonedx/cyclonedx-npm --call exit
npx cyclonedx-npm --of xml -o sbom.xml
```

### Python

#### cyclonedx-bom
https://cyclonedx-bom-tool.readthedocs.io/en/latest/usage.html

Does not 

```shell
pip install cyclonedx-bom
cyclonedx-py venv --gather-license-texts --PEP-639 > "${BOM_FILE}"
```

#### Syft

```shell
brew install syft

syft scan ./ -o cyclonedx-json=test-files/dependeny-track-syft-sbom.json
```

#### sbom4python

Requires Python < 3.13

https://pypi.org/project/sbom4python/
```shell
export PROJECT_NAME="dependency-tracker-4python"
export BOM_FILE="test-files/dependeny-track-4python-sbom.json"
sbom4python --system --sbom cyclonedx --format json -o "${BOM_FILE}"
```

## Integrations

### Trivy integration

https://docs.dependencytrack.org/datasources/trivy/
```text
http://trivy:8080
```

### Helm

https://github.com/DependencyTrack/helm-charts

## API usage

### Violation tests
- Check if event is processing: `/v1/event/token/{uuid}`
- Search project and retrieve UUID: `http://localhost:8081/api/v1/search/project?query=webapp`
- Get violations: `/v1/violation/project/{uuid}`

## Testing
### Prerequisites

- Docker machine requires > 4 GiB RAM

### First Startup
```shell
podman machine set --memory=6144
podman machine start
podman compose up
```

### Auth

- username: `admin`
- password: `admin`

### API-Key

- Goto *Teams* -> *Automation*
- Add *API-Key*
- Add *Permissions*

## Troubleshooting

### Symptom: ERROR [RequirementsVerifier] Dependency-Track requires a minimum of 4GB RAM (heap). Cannot continue. To fix, specify -Xmx4G (or higher) when executing Java.
- Increase VM memory

### Symptom: dependency failed to start: container dependency-tracker-apiserver-1 has no healthcheck configured
- Add health check to compose file or remove `service_healthy` dependency
- https://docs.dependencytrack.org/FAQ/

### Symptom: Request Entity too large
- Rancher Desktop uses Nginx ingress
- Use Podman

### Symptom: The principal does not have permission to create project.
- Add `PROJECT_CREATION_UPLOAD` to API key
