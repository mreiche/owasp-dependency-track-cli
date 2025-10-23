from owasp_dt.models import Project

def map_last_bom_import(project: Project):
    return project.last_bom_import if project.last_bom_import else 0

def compare_last_bom_import(a: Project, b: Project):
    return map_last_bom_import(b) - map_last_bom_import(a)
