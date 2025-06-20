[![Tests Status](https://github.com/mreiche/owasp-dependency-track-cli/actions/workflows/test-and-build.yml/badge.svg)](https://github.com/mreiche/owasp-dependency-track-cli/actions/workflows/test-and-build.yml)
[![Code Coverage Status](https://codecov.io/github/mreiche/owasp-dependency-track-cli/branch/main/graph/badge.svg)](https://app.codecov.io/github/mreiche/owasp-dependency-track-cli)
[![PyPI version](https://badge.fury.io/py/owasp-dependency-track-cli.svg)](https://badge.fury.io/py/owasp-dependency-track-cli)

# OWASP Dependency Track CLI

A CLI for CI/CD usage.

## Installation

```shell
pip install owasp-dependency-track-cli
```

## Usage

```shell
export OWASP_DTRACK_URL="http://localhost:8081/api"
export OWASP_DTRACK_VERIFY_SSL="False"
export OWASP_DTRACK_API_KEY="xyz"
export SEVERITY_THRESHOLD_HIGH="3"

owasp-dtrack-cli test --project-name webapp --auto-create test/files/test.sbom.xml
```

As Container runtime:

```shell
podman|docker \
 run --rm -v"$(pwd):$(pwd)" \
 -eOWASP_DTRACK_URL="http://192.168.1.100:8081/api" \
 -eOWASP_DTRACK_VERIFY_SSL="false" \
 -eOWASP_DTRACK_API_KEY="xyz" \
 ghcr.io/mreiche/owasp-dependency-track-cli:latest test --project-name webapp2 --auto-create "$(pwd)/test/files/test.sbom.xml"
```

## Commands

- `upload`: Uploads a SBOM only
- `analyze`: Analyzes a project by creating a report
- `test`: Uploads and analyzes a SBOM
- `metrics prometheus`: Provides Prometheus metrics as `owasp_dtrack_cvss_score` and `owasp_dtrack_violations` Gauge series
- `project upsert`: Upserts a project by file or JSON string

### Examples

```shell
owasp-dtrack-cli upload --parent-name "MyGroup" /path/to/sbom.json
owasp-dtrack-cli analyze --project-name "My project" --latest
owasp-dtrack-cli test --auto-create /path/to/sbom.json
owasp-dtrack-cli metrics prometheus --serve
owasp-dtrack-cli project upsert --json '{ "name": "My project" }'
```

## Environment variables
```shell
OWASP_DTRACK_URL="http://localhost:8081/api"  # Base-URL to OWASP Dependency Track API (mind '/api' as base path)
OWASP_DTRACK_VERIFY_SSL="False"               # Do not verify SSL
OWASP_DTRACK_API_KEY="xyz"                    # Your OWASP Dependency Track API Key (see below)
SEVERITY_THRESHOLD_[CRITICAL|HIGH|MEDIUM|LOW|UNASSIGNED]="-1"  # Threshold for findings severity
VIOLATION_THRESHOLD_[FAIL|WARN|INFO]="-1"     # Threshold for policy violations
ANALYZE_TIMEOUT_SEC="300"                     # Timeout for analyzation in seconds
PROJECT_TIMEOUT_SEC="20"                      # Timeout for searching the project by name in seconds
HTTPS_PROXY=""                                # URL for HTTP(S) proxy
```

## API-Key

Setup a user with API key and the following permissions:

1. Goto *Teams* -> *Automation*
2. Add *API-Key*
3. Add *Permissions*
   - SBOM_UPLOAD
   - PROJECT_CREATION_UPLOAD (for the auto-create feature)
   - VIEW_VULNERABILITY
   - VIEW_POLICY_VIOLATION

## Testing

### Start the test environment
```shell
cd test
podman|docker compose up
```

- Preconfigured user: `admin:admin2`
- Preconfigured API key: see `test/test.env`


### Update the test database
```shell
podman run -it --rm --network=test_default  -v "$(pwd)/test:/test" postgres:latest pg_dump -h postgres -d dtrack -U "dtrack" -p "5432" -f "/test/postgres-init/init.sql"
```

## References

- This CLI is using the Python API client: https://github.com/mreiche/owasp-dependency-track-python-client
