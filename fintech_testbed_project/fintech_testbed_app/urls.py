from django.urls import path
from . import views

urlpatterns = [
    path('home/', views.home, name='home'),
    path('', views.home),
    path('login/', views.login, name='login'),
    path('aboutus/', views.aboutus),
    path('services/', views.services),
    path('contactus/', views.contactus),
    path('register/', views.register, name='register'),
    path('account/', views.account, name='account')
]