from owasp_dt.models import Project
from datetime import datetime

def compare_last_bom_import(a: Project, b: Project):
    return b.last_bom_import - a.last_bom_import

day_format = "%Y-%m-%d"

def format_day(date: datetime):
    return date.strftime(day_format)
