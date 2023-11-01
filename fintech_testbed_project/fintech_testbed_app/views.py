from django.shortcuts import render
from django.shortcuts import render
from django.db import connection
from django.db.models import Q
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.contrib.auth import login as l_in
from django.http import HttpResponse
from django.conf import settings
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from .models import *
import pyotp
import bcrypt
from urllib.parse import urlencode

BYPASS_2FA_DEBUG = True

def home(request):
    page_args = {
        'is_logged_in': ('username' in request.session)
    }
    if page_args['is_logged_in']:
        page_args['username'] = request.session['username']
    return render(request, "home.html", page_args)

def login(request):
    # initialize the checks
    error_message = None
    valid_credentials = None
    
    # check if a button is clicked
    if request.method == 'POST':
        # check where the button was pressed
        form_type = request.POST.get('form_type', '')
        
        # check form type
        if form_type == 'enter-credentials': # user password check
            # get username and password typed
            username = request.POST['username']
            password = request.POST['password']

            # query to check if it exists in the db
            condition = Q(username=username)
            obj = Client.objects.filter(condition)
            obj_exists = obj.exists()

            # if found
            if obj_exists:
                salt = obj[0].salt
                hashed_password = obj[0].hashed_password
                
                hashed_entered_password = bcrypt.hashpw(password.encode('utf-8'), salt.encode('utf-8'))

                if hashed_entered_password == hashed_password.encode('utf-8'):
                    # update credentials
                    valid_credentials = True
                    
                    # generate 2FA code
                    secret = pyotp.random_base32()
                    totp = pyotp.TOTP(secret, interval=300)
                    
                    # set the session secret key and a temp user that will be
                    # discarded later
                    request.session['secret'] = secret
                    request.session['temp_user'] = username

                    # set the message to be sent
                    message = Mail(
                        from_email='bigbankwebservice@gmail.com',
                        to_emails= obj[0].email,
                        subject='Hello, World!',
                        plain_text_content=totp.now()
                    )

                    # attempt to send email
                    # NOTE COMMENTED OUT FOR NOW UNCOMMENT FOR EMAIL TO WORK
                    try:
                        sg = SendGridAPIClient(settings.SENDGRID_API_KEY)
                        # uncomment for email to be sent
                        #response = sg.send(message)
                    except Exception as e:
                        print("OTP Send Error:", e)
                else:
                    error_message = "Invalid Password"
            else:
                error_message = "Invalid Username"
        elif form_type == 'enter-OTP': # initialize 2FA code check
            # get session vars
            secret = request.session.get('secret')
            username = request.session.get('temp_user')

            # get token
            totp = pyotp.TOTP(secret, interval=300)
            token = request.POST['token']

            # if the token matches the current var
            if BYPASS_2FA_DEBUG or token == totp.now():
                # set the login user and remove the temp user
                request.session['temp_user'] = None
                request.session['username'] = username
                return home(request) 
            else:
                error_message = "Wrong code"
            
            # make sure the page stays on submit
            valid_credentials = True

    page_args = {
        'is_logged_in': ('username' in request.session),
        'error_message' : error_message,
        'valid_credentials' : valid_credentials
    }
    # stay on page
    return render(request, "login.html", page_args)

def services(request):
    page_args = {
        'is_logged_in': ('username' in request.session)
    }
    return render(request, "services.html", page_args)

def aboutus(request):
    page_args = {
        'is_logged_in': ('username' in request.session)
    }
    return render(request, "aboutus.html", page_args)

def contactus(request):
    page_args = {
        'is_logged_in': ('username' in request.session)
    }
    return render(request, "contactus.html", page_args)

def register(request):
    error_message = None  # Initialize error message to None
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        password_confirm = request.POST['password_confirm']

        
        # Check if the passwords match
        if password == password_confirm and email and not Client.objects.filter(username=username).exists():
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

            # Create a new client
            new_item = Client(username=username, email=email, salt=salt.decode('utf-8'), hashed_password=hashed_password.decode('utf-8'))
            
            new_item.save()

            # Redirect to a success page or home page
            return home(request)
        else:
            # Passwords don't match, set error message
            error_message = "Confirmed password must match the password."

    page_args = {
        "error_message": error_message,
        'is_logged_in': ('username' in request.session)
    }
    return render(request, "register.html", page_args)

def account(request):
    page_args = {
        'is_logged_in': ('username' in request.session)
    }

    if page_args['is_logged_in']:
        page_args['username'] = request.session['username']
    
    if 'username' in request.session:
        return render(request, "account.html", page_args)
    else:
        return render(request, "home.html")
