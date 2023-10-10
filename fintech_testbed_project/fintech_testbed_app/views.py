from django.shortcuts import render
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
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

def register(request):
    return render(request, "register.html")

def register(request):
    error_message = None  # Initialize error message to None

    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        password_confirm = request.POST['password_confirm']

        # Check if the passwords match
        if password == password_confirm:
            # Create a new user
            user = User.objects.create_user(username=username, email=email, password=password)
            user.save()

            # Log the user in
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)

            # Redirect to a success page or home page
            return redirect('home')
        else:
            # Passwords don't match, set error message
            error_message = "Confirmed password must match the password."

    return render(request, "register.html", {"error_message": error_message})