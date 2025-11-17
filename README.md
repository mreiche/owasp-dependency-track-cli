[![Tests Status](https://github.com/mreiche/owasp-dependency-track-cli/actions/workflows/test.yml/badge.svg)](https://github.com/mreiche/owasp-dependency-track-cli/actions/workflows/test.yml)
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
export OWASP_DTRACK_URL="http://localhost:8081"
export OWASP_DTRACK_VERIFY_SSL="False"
export OWASP_DTRACK_API_KEY="xyz"
export SEVERITY_THRESHOLD_HIGH="3"

owasp-dtrack-cli test --project-name webapp --auto-create test/files/test.sbom.xml
```

As Container runtime:

```shell
podman|docker \
 run --rm -v"$(pwd):$(pwd)" \
 -eOWASP_DTRACK_URL="http://192.168.1.100:8081" \
 -eOWASP_DTRACK_VERIFY_SSL="false" \
 -eOWASP_DTRACK_API_KEY="xyz" \
 ghcr.io/mreiche/owasp-dependency-track-cli:latest test --project-name webapp2 --auto-create "$(pwd)/test/files/test.sbom.xml"
```

## Commands

- `test`: Uploads a SBOM, analyzes and reports the according project
- `upload`: Uploads a SBOM only
- `analyze`: Analyzes and reports a project
- `report`: Creates a report only
- `metrics prometheus`: Provides Prometheus metrics as `owasp_dtrack_cvss_score` and `owasp_dtrack_violations` Gauge series
- `project upsert`: Upserts a project by file or JSON string
- `project remove-property`: Removes a property from a project
- `project activate`: Activates a project and adds the `keepActive` property
- `project deactivate`: Deactivates a project and removes the `keepActive` property

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
OWASP_DTRACK_URL="http://localhost:8081"  # Base-URL to OWASP Dependency Track
OWASP_DTRACK_VERIFY_SSL="False"           # Do not verify SSL
OWASP_DTRACK_API_KEY="xyz"                # Your OWASP Dependency Track API Key (see below)
SEVERITY_THRESHOLD_[CRITICAL|HIGH|MEDIUM|LOW|UNASSIGNED]="-1"  # Threshold for findings severity
VIOLATION_THRESHOLD_[FAIL|WARN|INFO]="-1" # Threshold for policy violations
CVSS_V3_THRESHOLD="-1"                    # Threshold for cumulated CVSS V3
CVSS_V2_THRESHOLD="-1"                    # Threshold for cumulated CVSS V2
ANALYZE_TIMEOUT_SEC="300"                 # Timeout for analyzation in seconds
PROJECT_TIMEOUT_SEC="20"                  # Timeout for searching the project by name in seconds
HTTPS_PROXY=""                            # URL for HTTP(S) proxy
LOG_LEVEL="info"                          # Logging verbosity (optional)
HTTPX_LOG_LEVEL="warning"                 # Log level of the httpx framework (optional)
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
   - PORTFOLIO_MANAGEMENT (for modifying projects)

## How it works

```mermaid
sequenceDiagram
    actor User
   User->>CLI: Provide SBOM
    CLI->>+OWASP DT: Clone project as new version
    OWASP DT->>-CLI: New project version
    CLI->>+OWASP DT: Upload and analyze SBOM
    OWASP DT->>-CLI: Return findings
    CLI->>OWASP DT: Deactivate older versions
    CLI->>+CLI: Generate findings report
    CLI->>+CLI: Analyze thresholds
    CLI->>User: Print findings report
    

```
Explanation of implementation behaviour.

### About patching a project
Every patch activates the project, to keep it deactivated, add to your patch:
```json
{ "active": false }
```
or use the `project deactivate` command afterwards.

### Uploading new project versions
The `upload` and `test` commands behave like the following:
- If the `--auto-create=true`, a new `--project-version` is provided and a previous uploaded version exists, it will be cloned as new version including properties and audit trail unless `--clone=false`
- All other project versions without `keepActive` property will be deactivated unless `--deactivate-others=false`. This property can be added manually or via the `project activate` command
- If `--latest` is set, this new project version will be marked as *Latest*

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
podman run -it --rm --network=test_default  -v "$(pwd)/test:/test" postgres:17-alpine pg_dump -h postgres -d dtrack -U "dtrack" -p "5432" -f "/test/postgres-init/init.sql"
```

## More OWASP Dependency Track utils

This library is part of a wider OWASP Dependency Track tool chain:
- OWASP Dependency Track Python API client: https://github.com/mreiche/owasp-dependency-track-python-client
- OWASP Dependency Track CLI: https://github.com/mreiche/owasp-dependency-track-cli
- OWASP Dependency Track Azure DevOps Sync: https://github.com/mreiche/owasp-dependency-track-azure-devops
