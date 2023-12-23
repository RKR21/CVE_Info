from django.contrib import admin
from django.urls import path, include
from . import views

urlpatterns = [
    path('search/', views.generate_report, name='generate_report'),
    
]
