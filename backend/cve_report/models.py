from django.db import models

# Create your models here.

class CVEReport(models.Model):
    name = models.CharField(max_length = 20)
    description = models.TextField()
    vector = models.CharField(max_length = 50)
    nvd_links = models.TextField()
    google_links = models.TextField()

    cvss_two = models.FloatField(null = True, blank = True)
    cvss_three = models.FloatField(null = True, blank = True)

    cwe_id = models.CharField(max_length = 10)
    cwe_name = models.CharField(max_length = 200)
    cwe_link = models.URLField()
    exploit_link = models.URLField()     # take to exploit-db search page iff there is an exploit(s)

    def __str__(self):
        return self.name