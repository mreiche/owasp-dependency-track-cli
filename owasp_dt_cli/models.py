from owasp_dt.models import Project, ProjectProperty, ProjectPropertyPropertyType, Finding

program_name = "owasp-dtrack-cli"


def map_last_bom_import(project: Project):
    return project.last_bom_import if project.last_bom_import else 0

def map_cvss(finding: Finding):
    if finding.vulnerability.cvss_v3_base_score:
        return finding.vulnerability.cvss_v3_base_score
    elif finding.vulnerability.cvss_v2_base_score:
        return finding.vulnerability.cvss_v2_base_score
    else:
        return 0

def compare_last_bom_import(a: Project, b: Project):
    return map_last_bom_import(b) - map_last_bom_import(a)

def compare_finding_score(a: Finding, b: Finding):
    return map_cvss(b) - map_cvss(a)

keep_active_property = ProjectProperty(
    group_name=program_name,
    property_name="keepActive",
    property_type=ProjectPropertyPropertyType.BOOLEAN,
    property_value="TRUE",
)
