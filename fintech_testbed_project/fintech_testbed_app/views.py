from django.shortcuts import render, redirect
from django.db import connection, connections
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
from django.urls import reverse
from datetime import datetime
from fintech_testbed_app import views_helpers as helper
import json
import psycopg2
from django.http import JsonResponse

############### Things for logging ######################
import logging
import boto3
from botocore.exceptions import NoCredentialsError
import time

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

import requests

# Function to send logs to AWS CloudWatch Logs
def send_logs(log_group, log_stream, log_data):
    try:
        # Configure your AWS credentials and region
        aws_access_key_id = 'your aws key' #'your aws key'
        aws_secret_access_key = 'your aws secerete'#'your aws secerete'
        aws_region = 'us-west-2'

        client = boto3.client('logs', region_name=aws_region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

        # Create or retrieve the log group
        try:
            client.create_log_group(logGroupName=log_group)
            print(f"Log group '{log_group}' created successfully.")
        except Exception as e:
            if 'ResourceAlreadyExistsException' in str(e):
                print(f"Log group '{log_group}' already exists.")
            else:
                raise



         # Check if the log stream exists
        log_stream_exists = False
        try:
            response = client.describe_log_streams(logGroupName=log_group, logStreamNamePrefix=log_stream)
            log_streams = response.get('logStreams', [])
    
            if log_streams:
                log_stream_exists = True
                print(f"Log stream '{log_stream}' already exists in '{log_group}'.")
            else:
                log_stream_exists = False
        except Exception as e:
            if 'ResourceNotFoundException' in str(e):
                # Log stream doesn't exist, so create it
                response = client.create_log_stream(logGroupName=log_group, logStreamName=log_stream)
                print(f"Log stream '{log_stream}' created successfully.")
            else:
                print(f"Error: {e}")

        # Create log stream if it doesn't exist
        if not log_stream_exists:
            response = client.create_log_stream(logGroupName=log_group, logStreamName=log_stream)
            print(f"Log stream '{log_stream}' created successfully.")
        # Send logs to CloudWatch Logs
        response = client.put_log_events(
            logGroupName=log_group,
            logStreamName=log_stream,
            logEvents=[
                {
                    'timestamp': int(round(time.time() * 1000)),
                    'message': log_data,
                },
            ],
        )

        print(f"Logs sent successfully to {log_group}/{log_stream}")
    except NoCredentialsError:
        print("Credentials not available")
    except Exception as e:
        print(f"Error: {e}")


################################################
BYPASS_2FA_DEBUG = False
EMAIL_ENABLED = True
HARDCODED_MANAGER_PIN = '0423'

# transfer page that makes transfers between accounts
def transfer(request):
    # arguments being sent to html
    page_args = {
        'admin_is_logged_in': ('admin_username' in request.session),
        'client_is_logged_in': ('username' in request.session)
    }

    # force redirect if permission is denied
    if not page_args['client_is_logged_in']:
        return redirect('/')
    
    # get the user through helper user function
    result = helper.get_user(request.session['username'])
    username = result[0]
    balance = result[1]
    user_id = str(result[2])
    page_args["balance"] = balance

    # check if a button is clicked
    if request.method == 'POST':
        # check where the button was pressed
        form_type = request.POST.get('form_type', '')

        # check form submission type
        if form_type == 'transfer-user':        
            # get page inputs
            recipient = request.POST['recipient']
            transfer_amount = helper.string_to_float(request.POST['transfer-amount'])
            description = request.POST['description']
            
            # get recipient through helper function
            recipient = helper.get_user(recipient)

            # check if recipient exists
            if recipient:
                # get info fneeded for transfer
                recipient_user = recipient[0]
                recipient_id = str(result[2])

                # make transfer between accounts
                if transfer_amount and transfer_amount <= balance and transfer_amount > 0:
                    # make transaction and update both user balances and show updated balance to page
                    helper.account_transfer(username, recipient_user, transfer_amount, description, None)
                    result = helper.get_user(request.session['username'])
                    page_args["balance"] = result[1]
                    
                    #send logs to AWS
                    logger.info('Transfer Succesful')
                    send_logs("Fintech-DLP-BigBank", "Transfer", 'Transfer Succesful')
                else:
                    #send logs to AWS
                    logger.info('Transfer Fail')
                    send_logs("Fintech-DLP-BigBank", "Transfer", 'Transfer Fail')
                    print("Error")
            else:
                #send logs to AWS
                logger.info('Transfer Fail')
                send_logs("Fintech-DLP-BigBank", "Transfer", 'Transfer Fail')
                print("Error")
    
    return render(request, "transfer.html", page_args)

# admin page to handout money to clien accounts
def cashier(request):
    local_variables = locals()

    # Check if the variable exists in the local variables dictionary
    page_args = {
        'admin_is_logged_in': ('admin_username' in request.session)
    }
    error_message = ''

    # if admin is not logged in exit page
    if 'admin_username' not in request.session:
        return redirect('/')

    # check if a button is clicked
    if request.method == 'POST':
        # check where the button was pressed
        form_type = request.POST.get('form_type', '')
        if form_type == 'checkout-user':            # select user
            username = request.POST['username']

            # get the user
            result = helper.get_user(username)

            # check if there is a user
            if result:
                # get values and update form
                username = result[0]
                balance = result[1]
                user_id = str(result[2])

                # set session
                request.session['cashier_username'] = username
                request.session['cashier_balance'] = balance
                request.session['cashier_id'] = user_id
            else:
                # remove session variables and notify error
                if "cashier_username" in request.session:
                    del request.session['cashier_username']
                    del request.session['cashier_balance']
                    del request.session['cashier_id']

                    error_message = "User not found."
                    page_args['error_message'] = error_message

        elif form_type == 'make-deposit':           # make deposit
            # check the form info
            deposit = request.POST['deposit-amount']
            deposit = helper.string_to_float(deposit)
            
            # if there is a valid deposit input
            if deposit:
                # get session variables
                username = request.session.get('cashier_username')
                balance = helper.string_to_float(request.session['cashier_balance'])
                user_id = request.session.get('cashier_id')

                # check if deposit needs to be checked by manager pin
                if deposit >= 5000:
                    manager_pin = request.POST.get('manager-pin')
                    if manager_pin == HARDCODED_MANAGER_PIN:
                        # make transaction
                        helper.make_transaction(None, username, deposit, "cashier check", request.session['admin_username'])
                        # make update balance
                        helper.update_balance(username, deposit)
                    else:
                        error_message = 'Invalid manager pin. Deposit is over $5000'
                else:
                    # make transaction
                    helper.make_transaction(None, username, deposit, "cashier check", request.session['admin_username'])
                    # make update balance
                    helper.update_balance(username, deposit)
            else:
                error_message = 'Invalid deposit amount.'
                
        elif form_type == 'make-withdrawal':    # make withdrawal
            # check form info
            withdraw = request.POST['withdraw-amount']
            withdraw = helper.string_to_float(withdraw)

            # if there is a valid withdraw
            if withdraw:
                username = request.session.get('cashier_username')
                balance = helper.string_to_float(request.session.get('cashier_balance'))
                
                user_id = request.session.get('cashier_id')

                # check balance and withdraw if amount is valid
                if withdraw <= balance:
                    # If withdrawal >=$5000, then require manager pin:
                    if withdraw >= 5000:
                        manager_pin = request.POST.get('manager-pin')
                        if manager_pin == HARDCODED_MANAGER_PIN:
                            # make transaction
                            helper.make_transaction(username, None, withdraw, "cashier check", request.session['admin_username'])
                            # make update balance
                            helper.update_balance(username, withdraw*-1)
                        else:
                            error_message = 'Invalid manager pin. Withdrawal is over $5000'
                    else:
                        # make transaction
                        helper.make_transaction(username, None, withdraw, "cashier check", request.session['admin_username'])
                        # make update balance
                        helper.update_balance(username, withdraw*-1)
                else:
                    error_message = 'Invalid withdrawal. Amount is higher than balance.'
            else:
                error_message = 'Invalid withdrawal amount.'
        
        # update username details
        if "cashier_username" in request.session:
            result = helper.get_user(request.session.get('cashier_username'))
            username = result[0]
            balance = result[1]
            user_id = str(result[2])

            request.session['cashier_username'] = username
            request.session['cashier_balance'] = balance
            request.session['cashier_id'] = user_id

            page_args = {
                'admin_is_logged_in': ('admin_username' in request.session),
                'client_is_logged_in': ('username' in request.session),
                "username": username,
                "balance": balance,
                "error_message": error_message
            }

    #send logs to AWS
    logger.info('Cashier login')
    send_logs("Fintech-DLP-BigBank", "Cashier", 'Cashier login succesful')

    return render(request, "cashiers-interface.html", page_args)

# home page the main view when first logged in or on the website
def home(request):
    page_args = {
        'client_is_logged_in': ('username' in request.session),
        'admin_is_logged_in': ('admin_username' in request.session)
    }
    
    # sets page based on what account is logged in if any
    if page_args['client_is_logged_in']:
        page_args['username'] = request.session['username']
    elif page_args['admin_is_logged_in']:
        page_args['admin_username'] = request.session['admin_username']

    # if the user inputs a login form on home
    if request.method == 'POST':
        form_type = request.POST.get('form_type', '')
        
        # check submitted for
        if form_type == 'homepage-enter-credentials':
            # set new url and sets session variables for that page
            login_url = reverse('login')
            username = request.POST['username']
            password = request.POST['password']
            request.session['login_query_processed'] = False
            request.session['home_username_input'] = username
            request.session['home_password_input'] = password
            return redirect(login_url)
    
    #send logs to AWS
    logger.info('Home page visited')
    send_logs("Fintech-DLP-BigBank", "home page", 'Home page visited')
    return render(request, "home.html", page_args)

# the login page for clients
def login(request):
    # initialize the checks
    error_message = None
    valid_credentials = None
    
    # check user credentials to see if they are eligable to log in
    def check_credentials(request, username, password):
        valid_credentials = False
        error_message = None

        # query to check if it exists in the db        
        result = helper.get_user(username)

        # if username exists
        if result:
            # get encrypted password details
            salt = result[4]
            hashed_password = result[5]
            email = result[3]
            
            # descrypt password based on input
            hashed_entered_password = bcrypt.hashpw(password.encode('utf-8'), salt.encode('utf-8'))

            # check if password correct
            if hashed_entered_password == hashed_password.encode('utf-8'):
                # update credentials
                valid_credentials = True
                        
                # generate 2FA code
                secret = pyotp.random_base32()
                totp = pyotp.TOTP(secret, interval=300)
                print(totp.now())
                        
                # set the session secret key and a temp user that will be
                # discarded later
                request.session['secret'] = secret
                request.session['temp_user'] = username

                # set the message to be sent
                message = Mail(
                    from_email='bigbankwebservice@gmail.com',
                    to_emails= email,
                    subject='BigBank Verification',
                    plain_text_content=totp.now()
                )

                # attempt to send email
                # NOTE COMMENTED OUT FOR NOW UNCOMMENT FOR EMAIL TO WORK
                try:
                    sg = SendGridAPIClient(settings.SENDGRID_API_KEY)
                    
                    # send email if it is enabled
                    if EMAIL_ENABLED:
                        response = sg.send(message)
                except Exception as e:
                    print("OTP Send Error:", e)
                    #send logs to AWS
                    logger.info('Login')
                    send_logs("Fintech-DLP-BigBank", "Login", 'Login Failed')
            else:
                error_message = "Invalid Login"
                #send logs to AWS
                logger.info('Login')
                send_logs("Fintech-DLP-BigBank", "Login", 'Login Failed')           
        else:
            error_message = "Invalid Login"
            #send logs to AWS
            logger.info('Login')
            send_logs("Fintech-DLP-BigBank", "Login", 'Login Failed')
        
        return {
                    "valid_credentials": valid_credentials, 
                    "error_message": error_message
                }
    
    # if the user logged in on the homepage
    if 'login_query_processed' in request.session:
        # check if both inputs where made and check if the login isn't repeating
        if (
            'home_username_input' in request.session and 
            'home_password_input' in request.session and 
            not request.session.get('login_query_processed')
        ):
            # check credentials of the user
            result = check_credentials(request, request.session['home_username_input'], request.session['home_password_input'])
            
            # get result info and update page arguments to determine if the next step can be made
            error_message = result['error_message']
            valid_credentials = result['valid_credentials']
            page_args = {
                'client_is_logged_in': ('username' in request.session),
                'error_message' : error_message,
                'valid_credentials' : valid_credentials,
                'username_sendback' : request.session['home_username_input']
            }

            # delete repeated variables
            del request.session['home_username_input']
            del request.session['home_password_input']
            request.session['login_query_processed'] = True
            
            return render(request, "login.html", page_args)

    # check if a button is clicked
    if request.method == 'POST':
        # check where the button was pressed
        form_type = request.POST.get('form_type', '')
        
        # check form type
        if form_type == 'enter-credentials': # user password check
            username = request.POST['username']
            password = request.POST['password']
            result = check_credentials(request, username, password)
            error_message = result['error_message']
            valid_credentials = result['valid_credentials']
            page_args = {
                'admin_is_logged_in': ('admin_username' in request.session),
                'client_is_logged_in': ('username' in request.session),
                'error_message' : error_message,
                'valid_credentials' : valid_credentials,
                'username_sendback' : username
            }
            return render(request, "login.html", page_args)
        elif form_type == 'enter-OTP': # initialize 2FA code check
            # get session vars
            secret = request.session.get('secret')
            username = request.session.get('temp_user')

            if 'login_query_processed' in request.session:
                del request.session['login_query_processed']

            # get token
            totp = pyotp.TOTP(secret, interval=300)
            token = request.POST['token']

            # if the token matches the current var
            if BYPASS_2FA_DEBUG or token == totp.now():
                # set the login user and remove the temp user
                del request.session['temp_user']
                del request.session['secret']
                request.session['username'] = username
                
                # send logs to AWS
                logger.info('Login')
                send_logs("Fintech-DLP-BigBank", "Login", 'Login Succesful')
                return redirect('/')
            else:
                error_message = "Wrong code"
                #send logs to AWS
                logger.info('Login')
                send_logs("Fintech-DLP-BigBank", "Login", 'Login Failed, wrong otp')
            
            # make sure the page stays on submit
            valid_credentials = True

    page_args = {
        'admin_is_logged_in': ('admin_username' in request.session),
        'client_is_logged_in': ('username' in request.session),
        'error_message' : error_message,
        'valid_credentials' : valid_credentials,
        'username_sendback' : ''
    }

    # stay on page
    return render(request, "login.html", page_args)

# the login page for admins
def admin_login(request):

    def get_ip_info():
        try:
            response = requests.get('https://ipinfo.io/json')
            if response.status_code == 200:
                json_response = response.json()
                return json_response.get('city')
            else:
                return None
        except requests.RequestException as e:
            print(f"Request Exception: {e}")
            return None


    if get_ip_info() != 'Pullman':
        page_args = {
            'admin_is_logged_in': ('admin_username' in request.session),
            'client_is_logged_in': ('username' in request.session),
            'error_message' : "Not in Pullman",
            'valid_credentials' : False,
            'username_sendback' : ''
        }

        # stay on page
        return render(request, "admin-login.html", page_args)
    
    # get all admins to see if any exist
    results = helper.admin_all_select()

    # set default admin if no admins are there
    if results == None:
        helper.admin_register("BigBank", "bigbankwebservice@gmail.com", "BankMainAdmin1!")
        helper.admin_register("Subu", "b.kandaswamy@wsu.edu", "BankMainAdmin1!")
        helper.admin_register("Ethan", "ethan.mcphee@wsu.edu", "BankMainAdmin1!")
        helper.admin_register("Jean", "jean.cho@wsu.edu", "BankMainAdmin1!")
        helper.admin_register("Sam", "samuel.zhang@wsu.edu", "BankMainAdmin1!")
        helper.admin_register("Derek", "sadler_derek@comcast.net", "BankMainAdmin1!")
        helper.admin_register("Jason", "jasonburt@google.com", "BankMainAdmin1!")

    # initialize the checks
    error_message = None
    valid_credentials = None
    
    # check user credentials
    def check_credentials(request, username, password):
        # vars to return to page
        valid_credentials = False
        error_message = None

        # query to check if it exists in the db        
        result = helper.get_admin_user(username)

        # if user exists
        if result:
            # set result variables
            salt = result[4]
            hashed_password = result[3]
            email = result[2]
            
            # get hashed password and check if it is correct        
            hashed_entered_password = bcrypt.hashpw(password.encode('utf-8'), salt.encode('utf-8'))
            if hashed_entered_password == hashed_password.encode('utf-8'):
                # update credentials
                valid_credentials = True
                        
                # generate 2FA code
                secret = pyotp.random_base32()
                totp = pyotp.TOTP(secret, interval=300)
                print(totp.now())
                        
                # set the session secret key and a temp user that will be
                # discarded later
                request.session['admin_secret'] = secret
                request.session['admin_temp_user'] = username

                # set the message to be sent
                message = Mail(
                    from_email='bigbankwebservice@gmail.com',
                    to_emails= email,
                    subject='BigBank Verification',
                    plain_text_content=totp.now()
                )

                # attempt to send email
                # NOTE COMMENTED OUT FOR NOW UNCOMMENT FOR EMAIL TO WORK
                try:
                    sg = SendGridAPIClient(settings.SENDGRID_API_KEY)
                    
                    # send email if it is enabled
                    if EMAIL_ENABLED:
                        response = sg.send(message)
                except Exception as e:
                    print("OTP Send Error:", e)
                    
                    #send logs to AWS
                    #logger.info('Login')
                    #send_logs("Fintech-DLP-BigBank", "Login", 'Login Failed')
            else:
                error_message = "Invalid Login"
                #send logs to AWS
                #logger.info('Login')
                #send_logs("Fintech-DLP-BigBank", "Login", 'Login Failed')           
        else:
            error_message = "Invalid Login"
            
            #send logs to AWS
            #logger.info('Login')
            #send_logs("Fintech-DLP-BigBank", "Login", 'Login Failed')
        
        return {
                    "valid_credentials": valid_credentials, 
                    "error_message": error_message
                }

    # check if a button is clicked
    if request.method == 'POST':
        # check where the button was pressed
        form_type = request.POST.get('form_type', '')
        
        # check form type
        if form_type == 'enter-credentials': # user password check
            username = request.POST['username']
            password = request.POST['password']
            result = check_credentials(request, username, password)
            error_message = result['error_message']
            valid_credentials = result['valid_credentials']
            page_args = {
                'admin_is_logged_in': ('admin_username' in request.session),
                'client_is_logged_in': ('username' in request.session),
                'error_message' : error_message,
                'valid_credentials' : valid_credentials,
                'username_sendback' : username
            }
            return render(request, "admin-login.html", page_args)
        elif form_type == 'enter-OTP': # initialize 2FA code check
            # get session vars
            secret = request.session.get('admin_secret')
            username = request.session.get('admin_temp_user')

            # get token
            totp = pyotp.TOTP(secret, interval=300)
            token = request.POST['token']

            # if the token matches the current var
            if BYPASS_2FA_DEBUG or token == totp.now():
                # set the login user and remove the temp user
                del request.session['admin_temp_user']
                del request.session['admin_secret']
                request.session['admin_username'] = username
                
                # send logs to AWS
                #logger.info('Login')
                #send_logs("Fintech-DLP-BigBank", "Login", 'Login Succesful')
                return redirect('/')
            else:
                error_message = "Wrong code"
                #send logs to AWS
                #logger.info('Login')
                #send_logs("Fintech-DLP-BigBank", "Login", 'Login Failed, wrong otp')
            
            # make sure the page stays on submit
            valid_credentials = True

    page_args = {
        'admin_is_logged_in': ('admin_username' in request.session),
        'client_is_logged_in': ('username' in request.session),
        'error_message' : error_message,
        'valid_credentials' : valid_credentials,
        'username_sendback' : ''
    }

    # stay on page
    return render(request, "admin-login.html", page_args)

# page that shows website services
def services(request):
    page_args = {
        'client_is_logged_in': ('username' in request.session),
        'admin_is_logged_in': ('admin_username' in request.session)
    }
    return render(request, "services.html", page_args)

# page that shows bigbank info
def aboutus(request):
    page_args = {
        'client_is_logged_in': ('username' in request.session),
        'admin_is_logged_in': ('admin_username' in request.session)
    }
    return render(request, "aboutus.html", page_args)

# page to contact bigbank
def contactus(request):
    page_args = {
        'client_is_logged_in': ('username' in request.session),
        'admin_is_logged_in': ('admin_username' in request.session)
    }

    # if the form is submitted to contact the bank
    if request.method == 'POST':
        # get input details
        name = request.POST['name']
        email = request.POST['email']
        message = request.POST['message']
        header = name + " at " + email

        # set the message to be sent
        message = Mail(
            from_email='bigbankwebservice@gmail.com',
            to_emails= 'bigbankwebservice@gmail.com',
            subject= header,
            plain_text_content=message
        )

        # attempt to send email
        # NOTE COMMENTED OUT FOR NOW UNCOMMENT FOR EMAIL TO WORK
        try:
            sg = SendGridAPIClient(settings.SENDGRID_API_KEY)
                    
            # send email if it is enabled
            if EMAIL_ENABLED:
                response = sg.send(message)
        except Exception as e:
             print("OTP Send Error:", e)

    return render(request, "contactus.html", page_args)

# registration page
def register(request):
    error_message = None  # Initialize values to None or empty string
    username = ''
    firstname = ''
    lastname = ''
    email = ''
    
    # if a form is posted
    if request.method == 'POST':
        # get inputs
        username = request.POST['username']
        firstname = request.POST['first-name']
        lastname = request.POST['last-name']
        email = request.POST['email']
        password = request.POST['password']
        password_confirm = request.POST['password_confirm']
        
        # check business check
        if "business_check" in request.POST:
            business_checked = True
        else:
            business_checked = False

        # Check for password strength
        if not is_strong_password(password):
            error_message = "Password is not strong enough."
        elif password != password_confirm:
            error_message = "Confirmed password must match the password."
        elif not email or Client.objects.filter(username=username).exists():
            error_message = "Email or username already exists."
        else:
            # Check if the passwords match
            if password == password_confirm and email and not Client.objects.filter(username=username).exists():
                salt = bcrypt.gensalt()
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
                
                db_connection = connections['default']
                cursor = db_connection.cursor()

                # Create a new client
                new_item_query = "INSERT INTO fintech_testbed_app_client (id, username, email, salt, hashed_password, balance, is_business) VALUES (%s, %s, %s, %s, %s, %s, %s)"
                params = (uuid.uuid4(), username, email, salt.decode('utf-8'), hashed_password.decode('utf-8'), 0, business_checked)
                cursor.execute(new_item_query, params)
                db_connection.commit()
                db_connection.close()

                #send logs to AWS
                logger.info('Register')
                send_logs("Fintech-DLP-BigBank", "Register", 'Registration Succesful')
                # Redirect to a success page or home page
                return redirect('/')
            else:
                # Passwords don't match, set error message
                error_message = "Confirmed password must match the password."

    page_args = {
        "error_message": error_message,
        'client_is_logged_in': ('username' in request.session),
        'admin_is_logged_in': ('admin_username' in request.session),
        'username_sendback': username,
        'firstname_sendback': firstname,
        'lastname_sendback': lastname,
        'email_sendback': email
    }
    #send logs to AWS
    logger.info('Register')
    send_logs("Fintech-DLP-BigBank", "Register", 'Registration Failed')
    return render(request, "register.html", page_args)

# main user account page
def account(request):
    page_args = {
        'admin_is_logged_in': ('admin_username' in request.session),
        'client_is_logged_in': ('username' in request.session)
    }

    # set page #
    if 'account_page_num' not in request.session:
        request.session['account_page_num'] = 0 

    # check if a button is clicked
    if request.method == 'POST':
        # check where the button was pressed
        form_type = request.POST.get('form_type', '')
        
        # check form type
        if form_type == 'next-page':                    # go to next page
            request.session['account_page_num'] += 1
        elif form_type == 'last-page':                  # go to previous page
            request.session['account_page_num'] -= 1
        elif form_type == 'flag-transaction':           # add a new transaction flag
            description = request.POST["description"]
            transaction_id = request.session["selected_transaction"]

            db_connection = connections['default']
            cursor = db_connection.cursor()
            

            helper.make_flagged_transaction(uuid.uuid4(), description, transaction_id, str(request.session['username']), str(datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

            del request.session["selected_transaction"]
        else:                                               # transaction clicked
            page_args["selected_transaction"] = request.POST['transaction_id']
            page_args["transaction_date"] = request.POST["date"]
            page_args["transaction_sender"] = request.POST["sender"]
            page_args["transaction_receiver"] = request.POST["receiver"]
            page_args["transaction_balance"] = request.POST["balance"]
            request.session["selected_transaction"] = request.POST['transaction_id']

    page_args['account_page_num'] = request.session['account_page_num']  

    # check if the user is logged in and print the user info
    if page_args['client_is_logged_in']:
        
        # Populate username
        page_args['username'] = request.session['username']
        
        db_connection = connections['default']
        cursor = db_connection.cursor()

        # get the user
        sql_query = "SELECT id, balance, is_business FROM fintech_testbed_app_client WHERE username = %s"
        params = (page_args['username'],)
        cursor.execute(sql_query, params)
        result = cursor.fetchall()
        result = result[0]
        user_id = result[0]
        balance = result[1]
        is_business = result[2]

        page_args['is_business'] = is_business

        # get transactions from user account
        sql_query = """
            SELECT t.datetime, t.description, t.sender, t.reciever, t.balance, t.id, t.admin_cashier
            FROM fintech_testbed_app_transactions AS t
            JOIN fintech_testbed_app_client AS u ON t.sender = u.username OR t.reciever = u.username
            WHERE u.username = %s
            ORDER BY t.datetime DESC;
        """

        params = (page_args['username'],)
        cursor.execute(sql_query, params)
        result = cursor.fetchall()
        db_connection.commit()
        db_connection.close()

        page = request.session['account_page_num']
        page_args['transactions'] = result[page*11:(page+1)*11]
        page_args['page_element_size'] = (page+1) * 11
        page_args['page_element_max'] = len(result)
        # Populate balance
        page_args['balance'] = balance #change this to query
        #send logs to AWS
        logger.info('Account')
        send_logs("Fintech-DLP-BigBank", "Account", 'Account Page visited')
        
        return render(request, "account.html", page_args)
    else:
        #send logs to AWS and redirect user home
        logger.info('Account')
        send_logs("Fintech-DLP-BigBank", "Account", 'Attempt to visit account page has failed')
        return redirect('/')

# admin page to review flagged transactions
def flagged_transaction(request):
    page_args = {
        'admin_is_logged_in': ('admin_username' in request.session),
        'client_is_logged_in': ('username' in request.session)
    }

    # if admin is not logged in exit page
    if 'admin_username' not in request.session:
        return render(request, "home.html")

    # set page #
    if 'flagged_transaction_page_num' not in request.session:
        request.session['flagged_transactions_page_num'] = 0 

    if request.method == 'POST':
        # check where the button was pressed
        form_type = request.POST.get('form_type', '')
        
        # check form type
        if form_type == 'next-page':
            request.session['account_page_num'] += 1
        elif form_type == 'last-page':
            request.session['account_page_num'] -= 1
        elif form_type == 'cancel-transaction' or  form_type == 'reject-flag':      # admin has made decision on a selected transaction
            # get needed details
            description = request.POST["description"]
            flagged_transaction_id = request.session["selected_flagged_transaction"]
            flagged_transaction_user = request.session["selected_flagged_transaction_user"]
            
            # get the user of the flagged transaction
            result = helper.get_user(flagged_transaction_user)
            email = result[3]
            
            # set the message to be sent
            message = Mail(
                from_email='bigbankwebservice@gmail.com',
                to_emails= email,
                subject='BigBank Flagged Transaction Findings',
                plain_text_content=description
            )

            # attempt to send email
            # NOTE COMMENTED OUT FOR NOW UNCOMMENT FOR EMAIL TO WORK
            try:
                sg = SendGridAPIClient(settings.SENDGRID_API_KEY)

                # send email if it is enabled
                if EMAIL_ENABLED:
                    response = sg.send(message)
            except Exception as e:
                print("OTP Send Error:", e)

            # perform a different action based on admin choice
            if form_type == 'cancel-transaction':   # undo transaction
                helper.undo_transaction(request.session["selected_flagged_transaction"], request.session["selected_flagged_transaction_id"], request.session["selected_flagged_transaction_sender"], request.session["selected_flagged_transaction_reciever"], request.session["selected_flagged_transaction_balance"])
            elif  form_type == 'reject-flag':       # reject the flag
                helper.delete_flagged_transaction(str(request.session["selected_flagged_transaction"]))
               
            # delete session vars
            del request.session["selected_flagged_transaction_id"] 
            del request.session["selected_flagged_transaction_user"]
            del request.session["selected_flagged_transaction_sender"]
            del request.session["selected_flagged_transaction_reciever"]
            del request.session["selected_flagged_transaction_balance"]
            del request.session["selected_flagged_transaction"]

        else:
            page_args["selected_flagged_transaction"] = request.POST['flagged_transaction_id']
            page_args["selected_transaction"] = request.POST['transaction_id']
            page_args["flagged_transaction_date"] = request.POST["date"]
            page_args["flagged_transaction_user"] = request.POST["user"]
            page_args["flagged_transaction_description"] = request.POST["description"]
            
            # get the transaction info
            result = helper.get_transaction_by_id(str(request.POST['transaction_id']))
            page_args["transaction_balance"] = result[1]
            page_args["transaction_date"] = result[2]
            page_args["transaction_description"] = result[3]
            page_args["transaction_reciever"] = result[4]
            page_args["transaction_sender"] = result[5]
            page_args["transaction_admin_cashier"] = result[6]

            # add transactions to session variables until discarded
            request.session["selected_flagged_transaction_id"] = page_args["selected_transaction"]
            request.session["selected_flagged_transaction_user"] = request.POST['user']
            request.session["selected_flagged_transaction_sender"] = page_args["transaction_sender"]
            request.session["selected_flagged_transaction_reciever"] = page_args["transaction_reciever"]
            request.session["selected_flagged_transaction_balance"] = helper.string_to_float(str(page_args["transaction_balance"]))
            request.session["selected_flagged_transaction"] = request.POST['flagged_transaction_id']

    page_args['flagged_transactions_page_num'] = request.session['flagged_transactions_page_num'] 

    result = helper.get_flagged_transactions()

    page = request.session['flagged_transactions_page_num']
    page_args['transactions'] = result[page*11:(page+1)*11]
    page_args['page_element_size'] = (page+1) * 11
    page_args['page_element_max'] = len(result)

    return render(request, "flagged-transaction-interface.html", page_args) 

# logout of all accounts and redirect back to login screen
def logout(request):
    # delete session variables
    if 'username' in request.session:
        del request.session['username']
    if 'admin_username' in request.session:
        del request.session['admin_username']

    #send logs to AWS
    logger.info('Logout')
    send_logs("Fintech-DLP-BigBank", "Logout", 'logout succesful')
    return redirect('/login')

# helper for password strength
def is_strong_password(password):
    # Check if the password is at least 8 characters long
    if len(password) < 8:
        return False

    # Check if the password contains at least one uppercase letter
    if not any(char.isupper() for char in password):
        return False

    # Check if the password contains at least one lowercase letter
    if not any(char.islower() for char in password):
        return False

    # Check if the password contains at least one digit
    if not any(char.isdigit() for char in password):
        return False

    # Check if the password contains at least one special character
    special_characters = "!@#$%^&*()-_+=<>?/[]{}|"
    if not any(char in special_characters for char in password):
        return False

    # If all criteria are met, the password is considered strong
    return True

# checks the login status and returns a json response depending on the status
def check_login_status(request):
    if 'username' in request.session or 'admin_username' in request.session:
        return JsonResponse({'status': 'logged_in'})
    else:
        return JsonResponse({'status': 'logged_out'})
