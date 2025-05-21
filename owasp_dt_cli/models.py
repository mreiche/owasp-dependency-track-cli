from owasp_dt.models import Project


def compare_last_bom_import(a: Project, b: Project):
    return b.last_bom_import - a.last_bom_import
