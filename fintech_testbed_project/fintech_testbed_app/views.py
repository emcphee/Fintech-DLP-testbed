from django.shortcuts import render

from django.http import HttpResponse

def home(request):
    return render(request, "home.html")

def login(request):
    return render(request, "login.html")

def services(request):
     return HttpResponse("Services Page Not Implemented")

def aboutus(request):
     return HttpResponse("About Us Page Not Implemented")

def contactus(request):
     return HttpResponse("Contact Us Page Not Implemented")