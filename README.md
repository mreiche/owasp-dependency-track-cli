# OWASP Dependency Tracker CLI

## Usage

### Test for findings

```shell
OWASP_DT_URL="http://localhost:8081/api"
OWASP_DT_VERIFY_SSL="False"
OWASP_DT_API_KEY="xyz"
SEVERITY_THRESHOLD_HIGH="3"

python main.py test --project-name webapp --auto-create test/test.sbom.xml
```

## Container usage

### Test for findings
```shell
podman|docker \
 run --rm -v"$(pwd):$(pwd)" \
 -eOWASP_DT_URL="http://192.168.1.100:8081/api" \
 -eOWASP_DT_VERIFY_SSL="false" \
 -eOWASP_DT_API_KEY="xyz" \
 ghcr.io/mreiche/owasp-dependency-track-cli:main test --project-name webapp2 --auto-create "$(pwd)/test/test.sbom.xml"
```

## Environment variables
```shell
OWASP_DT_URL="http://localhost:8081/api"  # Base-URL to OWASP Dependency Track API (mind '/api' as base path)
OWASP_DT_VERIFY_SSL="False"  # Do not verify SSL
OWASP_DT_API_KEY="xyz"  # You OWASP DT API Key
SEVERITY_THRESHOLD_HIGH="-1"  # Threshold for HIGH severity findings
SEVERITY_THRESHOLD_MEDIUM="-1"  # Threshold for MEDIUM severity findings
SEVERITY_THRESHOLD_LOW="-1"  # Threshold for LOW severity findings
SEVERITY_THRESHOLD_UNASSIGNED="-1"  # Threshold for UNASSIGNED severity findings
TEST_TIMEOUT_SEC="300"  # Timeout in seconds for waiting OWASP DT finished scanning
```

## API-Key

Setup a user with API key and the following permissions:

1. Goto *Teams* -> *Automation*
1. Add *API-Key*
1. Add *Permissions*
   - VIEW_VULNERABILITY
   - SBOM_UPLOAD
   - PROJECT_CREATION_UPLOAD (for the auto-create feature)


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


### Setup Azure OIDC

- https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc

## API usage

## API Documentation

- Open https://validator.swagger.io/ with `http://localhost:8081/api/openapi.json`

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
