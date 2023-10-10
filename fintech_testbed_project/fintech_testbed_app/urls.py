from django.urls import path
from . import views

urlpatterns = [
    path('home/', views.home),
    path('', views.home),
    path('login/', views.login),
    path('aboutus/', views.aboutus),
    path('services/', views.services),
    path('contactus/', views.contactus),
]