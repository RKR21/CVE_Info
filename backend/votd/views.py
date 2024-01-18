from django.utils import timezone

from django.http import HttpResponse
from django.shortcuts import render
from .tasks import test_func
from .models import VulnerabilityOfTheDay
from .tasks import find_votd
from .functions.generate_votd import votd_search

# Create your views here.
def home_votd(request):
    #test_func.delay()
    
    current_votd = VulnerabilityOfTheDay.objects.first()
    print(current_votd)
    if(current_votd == None or current_votd.date_posted != timezone.now().date()):
        new_votd = votd_search()     
        new_votd.save()
        print(new_votd)
        
        return render(request, 'home.html', {'current_votd':new_votd})

    print(timezone.now().date())
    if(current_votd.date_posted == timezone.now().date()):
        return render(request, 'home.html', {'current_votd':current_votd})
    