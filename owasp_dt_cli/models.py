from owasp_dt.models import Project, ProjectProperty, ProjectPropertyPropertyType

program_name = "owasp-dtrack-cli"


def map_last_bom_import(project: Project):
    return project.last_bom_import if project.last_bom_import else 0


def compare_last_bom_import(a: Project, b: Project):
    return map_last_bom_import(b) - map_last_bom_import(a)


keep_active_property = ProjectProperty(
    group_name=program_name,
    property_name="keepActive",
    property_type=ProjectPropertyPropertyType.BOOLEAN,
    property_value="TRUE",
)
