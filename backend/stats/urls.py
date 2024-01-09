from django.contrib import admin
from django.urls import path, include
from . import views
urlpatterns = [
    path('', views.search_view, name="search"),
    path('search_results/', views.get_stats, name="get_stats")
]
