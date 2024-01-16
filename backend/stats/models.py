from django.db import models
from django.utils import timezone
# Create your models here.
""" Stats to get:
* Average base score cvss 2 and/or three
* tallies of AC, AV, Au, C, I, A
* tallies of AV, AC, PR, UI, S, C, I, A
* populate dictionary = {year : [num CVEs in year]}
* populate dictionary = {year : [all base scores for year]} - > then calculate at the end
* tallies of CWE's for bar chart
"""
