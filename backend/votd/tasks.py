from celery import shared_task
from cve_report import models
from .functions import generate_votd
@shared_task(bind=True)
def test_func(self):
    report = models.CVEReport()
    report.name = "CVE-"
    report.save()
    for i in range(10):
        print(i)
        
@shared_task(bind=True)
def find_votd(self):
    report = generate_votd.votd_search()
    print(report)
    return report
