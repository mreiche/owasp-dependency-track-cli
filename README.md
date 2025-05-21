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
HTTPS_PROXY=""  # URL for for HTTP(S) proxy
```

## API-Key

Setup a user with API key and the following permissions:

1. Goto *Teams* -> *Automation*
1. Add *API-Key*
1. Add *Permissions*
   - VIEW_VULNERABILITY
   - SBOM_UPLOAD
   - PROJECT_CREATION_UPLOAD (for the auto-create feature)

## References

- This CLI is using the Python API client: https://github.com/mreiche/owasp-dependency-track-python-client
