from django.http import HttpResponse
from django.shortcuts import render
from .tasks import test_func
from .models import VulnerabilityOfTheDay
# Create your views here.
def home_votd(request):
    #test_func.delay()
    current_votd = VulnerabilityOfTheDay.objects.latest('date_posted')
    return render(request, 'home.html', {'current_votd':current_votd})