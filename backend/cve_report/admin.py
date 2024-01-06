from django.contrib import admin

from votd.models import VulnerabilityOfTheDay
from .models import CVEReport
# Register your models here.

admin.site.register(CVEReport)
admin.site.register(VulnerabilityOfTheDay)