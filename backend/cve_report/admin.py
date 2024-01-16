from django.contrib import admin

from votd.models import VulnerabilityOfTheDay
from .models import CVEReport
#from stats.models import QueryStats
# Register your models here.

admin.site.register(CVEReport)
admin.site.register(VulnerabilityOfTheDay)
#admin.site.register(QueryStats)