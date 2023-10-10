from django.shortcuts import render

from django.http import HttpResponse

def home(request):
    return render(request, "home.html")

def login(request):
    return render(request, "login.html")

def services(request):
     return render(request, "services.html")

def aboutus(request):
     return render(request, "aboutus.html")
def contactus(request):
    return render(request, "contactus.html")