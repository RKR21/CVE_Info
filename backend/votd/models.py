from django.utils import timezone
from django.db import models

class Tag(models.Model):
    name = models.CharField(max_length=50)
    def __str__(self):
        return self.name
class Link(models.Model):
    url = models.URLField()
    tags = models.ManyToManyField(Tag)
    def __str__(self):
        return self.url


class VulnerabilityOfTheDay(models.Model):
    name = models.CharField(max_length = 20)
    description = models.TextField()
    cvss_two_vector = models.CharField(max_length = 50)
    cvss_three_vector = models.CharField(max_length = 50)
    nvd_links = models.ManyToManyField(Link, related_name='nvd_links')
    

    cvss_two = models.FloatField(null = True, blank = True)
    cvss_three = models.FloatField(null = True, blank = True)

    date_published = models.DateField(default=timezone.now())
    nvd_link = models.URLField(default="#")
    cwe_id = models.CharField(max_length = 10)
    cwe_name = models.CharField(max_length = 200)
    cwe_link = models.URLField()
    date_posted = models.DateField()
    relevance_score = models.IntegerField()
    extended_description = models.TextField(default="None")
    def __str__(self):
        return self.name