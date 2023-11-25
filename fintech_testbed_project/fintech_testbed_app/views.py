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

BYPASS_2FA_DEBUG = True
HARDCODED_MANAGER_PIN = '0423'
def transfer(request):
    page_args = {
        'is_logged_in': ('username' in request.session)
    }
    
    def get_user(username):
        # get the user
        db_connection = connections['default']
        cursor = db_connection.cursor()
        sql_query = "SELECT username, balance, id FROM fintech_testbed_app_client WHERE username = %s"
        params = (username,)
        cursor.execute(sql_query, params)
        result = cursor.fetchall()
        db_connection.commit()
        db_connection.close()
        if result:
            result = result[0]
            return result
        else:
            return None

    def string_to_float(value):
        try:
            integer_value = float(value)
            return integer_value
        except ValueError:
            return None

    def make_transaction(sender, reciever, value):
        db_connection = connections['default']
        cursor = db_connection.cursor()

        try:
            # Begin the transaction
            db_connection.autocommit = False
            print("transaction id: ")
            print(user_id)
            new_transactions_query = "INSERT INTO fintech_testbed_app_transactions (id, sender, reciever, balance, datetime, description) VALUES (%s, %s, %s, %s, %s, %s)"
            params = (uuid.uuid4(), sender, reciever, value, str(datetime.now()), "cashier check")
            cursor.execute(new_transactions_query, params)

            db_connection.commit()
        except psycopg2.Error as e:
            # Rollback the transaction
            db_connection.rollback()
        finally:
            db_connection.close()
    
    def update_balance(username, balance):
        db_connection = connections['default']
        cursor = db_connection.cursor()
        query = "UPDATE fintech_testbed_app_client SET balance = balance + %s WHERE username = %s"

        # Execute the update query
        cursor.execute(query, (balance, username))
        db_connection.commit()
        db_connection.close()

    if not page_args['is_logged_in']:
        return render(request, "home.html")
    
    # get the user
    result = get_user(request.session['username'])
    username = result[0]
    balance = result[1]
    user_id = str(result[2])
    page_args["balance"] = balance

    # check if a button is clicked
    if request.method == 'POST':
        # check where the button was pressed
        form_type = request.POST.get('form_type', '')

        if form_type == 'transfer-user':    
            recipient = request.POST['recipient']
            transfer_amount = string_to_float(request.POST['transfer-amount'])
            description = request.POST['description']
            
            # get recipient
            recipient = get_user(recipient)

            # check if recipient exists
            if recipient:
                recipient_user = recipient[0]
                recipient_id = str(result[2])

                if transfer_amount and transfer_amount <= balance:
                    make_transaction(username, recipient_user, transfer_amount)
                    update_balance(username, -1 * transfer_amount)
                    update_balance(recipient_user, transfer_amount)
                    result = get_user(request.session['username'])
                    page_args["balance"] = result[1]
                else:
                    print("Error")
            else:
                print("Error")
    
    return render(request, "transfer.html", page_args)

def cashier(request):
    local_variables = locals()

    # Check if the variable exists in the local variables dictionary
    page_args = {
        'is_logged_in': ('username' in request.session),
    }

    def get_user(username):
        # get the user
        db_connection = connections['default']
        cursor = db_connection.cursor()
        sql_query = "SELECT username, balance, id FROM fintech_testbed_app_client WHERE username = %s"
        params = (username,)
        cursor.execute(sql_query, params)
        result = cursor.fetchall()
        db_connection.commit()
        db_connection.close()
        if result:
            result = result[0]
            return result
        else:
            return None

    def string_to_float(value):
        try:
            integer_value = float(value)
            return integer_value
        except ValueError:
            return None

    def make_transaction(sender, reciever, value):
        db_connection = connections['default']
        cursor = db_connection.cursor()

        try:
            # Begin the transaction
            db_connection.autocommit = False
            print("transaction id: ")
            print(user_id)
            new_transactions_query = "INSERT INTO fintech_testbed_app_transactions (id, sender, reciever, balance, datetime, description) VALUES (%s, %s, %s, %s, %s, %s)"
            params = (uuid.uuid4(), sender, reciever, value, str(datetime.now()), "cashier check")
            cursor.execute(new_transactions_query, params)

            db_connection.commit()
        except psycopg2.Error as e:
            # Rollback the transaction
            db_connection.rollback()
        finally:
            db_connection.close()
    
    def update_balance(username, balance):
        db_connection = connections['default']
        cursor = db_connection.cursor()
        query = "UPDATE fintech_testbed_app_client SET balance = balance + %s WHERE username = %s"

        # Execute the update query
        cursor.execute(query, (balance, username))
        db_connection.commit()
        db_connection.close()


    error_message = ''

    # check if a button is clicked
    if request.method == 'POST':
        # check where the button was pressed
        form_type = request.POST.get('form_type', '')
        if form_type == 'checkout-user':    # select user
            username = request.POST['username']

            # get the user
            result = get_user(username)

            if result:
                username = result[0]
                balance = result[1]
                print(balance)
                user_id = str(result[2])

                request.session['cashier_username'] = username
                request.session['cashier_balance'] = balance
                print(request.session['cashier_balance'])
                request.session['cashier_id'] = user_id
            else:

                if "cashier_username" in request.session:
                    del request.session['cashier_username']
                    del request.session['cashier_balance']
                    del request.session['cashier_id']

                    error_message = "User not found."
                    page_args['error_message'] = error_message

        elif form_type == 'make-deposit':   # make deposit
            deposit = request.POST['deposit-amount']
            deposit = string_to_float(deposit)
            
            if deposit:
                username = request.session.get('cashier_username')
                balance = string_to_float(request.session['cashier_balance'])
                user_id = request.session.get('cashier_id')

                if deposit >= 5000:
                    manager_pin = request.POST.get('manager-pin')
                    if manager_pin == HARDCODED_MANAGER_PIN:
                        # make transaction
                        make_transaction(username, username, deposit)
                        # make update balance
                        update_balance(username, deposit)
                    else:
                        error_message = 'Invalid manager pin. Deposit is over $5000'
                else:
                    # make transaction
                    make_transaction(username, username, deposit)
                    # make update balance
                    update_balance(username, deposit)
            else:
                error_message = 'Invalid deposit amount.'
                
        elif form_type == 'make-withdrawal':    # make withdrawal
            withdraw = request.POST['withdraw-amount']
            withdraw = string_to_float(withdraw)


            if withdraw:
                username = request.session.get('cashier_username')
                balance = string_to_float(request.session.get('cashier_balance'))
                
                user_id = request.session.get('cashier_id')

                # check balance and withdraw if amount is valid
                if withdraw <= balance:
                    # If withdrawal >=$5000, then require manager pin:
                    if withdraw >= 5000:
                        manager_pin = request.POST.get('manager-pin')
                        if manager_pin == HARDCODED_MANAGER_PIN:
                            # make transaction
                            make_transaction(username, username, withdraw)
                            # make update balance
                            update_balance(username, withdraw*-1)
                        else:
                            error_message = 'Invalid manager pin. Withdrawal is over $5000'
                    else:
                        # make transaction
                        make_transaction(username, username, withdraw)
                        # make update balance
                        update_balance(username, withdraw*-1)
                else:
                    error_message = 'Invalid withdrawal. Amount is higher than balance.'
            else:
                error_message = 'Invalid withdrawal amount.'
        
        # update username details
        if "cashier_username" in request.session:
            result = get_user(request.session.get('cashier_username'))
            username = result[0]
            balance = result[1]
            user_id = str(result[2])

            request.session['cashier_username'] = username
            request.session['cashier_balance'] = balance
            request.session['cashier_id'] = user_id

            page_args = {
                'is_logged_in': ('username' in request.session),
                "username": username,
                "balance": balance,
                "error_message": error_message
            }

    return render(request, "cashiers-interface.html", page_args)

def home(request):
    page_args = {
        'is_logged_in': ('username' in request.session)
    }
    if page_args['is_logged_in']:
        page_args['username'] = request.session['username']

    if request.method == 'POST':
        form_type = request.POST.get('form_type', '')
        print(form_type)
        if form_type == 'homepage-enter-credentials':
            login_url = reverse('login')
            username = request.POST['username']
            password = request.POST['password']
            login_url_with_params = f"{login_url}?username={username}&password={password}"
            request.session['login_query_processed'] = False
            return redirect(login_url_with_params)


    return render(request, "home.html", page_args)

def login(request):
    # initialize the database connection
    db_connection = connections['default']
    cursor = db_connection.cursor()

    # initialize the checks
    error_message = None
    valid_credentials = None
    
    def check_credentials(request, username, password):
        # query to check if it exists in the db
        sql_query = "SELECT salt, hashed_password, email FROM fintech_testbed_app_client WHERE username = %s"
        params = (username,)
        cursor.execute(sql_query, params)
        result = cursor.fetchall()
        
        if result:
            result = result[0]
            obj_exists = True
        else:
            obj_exists = False
            

        valid_credentials = False
        error_message = None

        # if found
        if obj_exists:
            salt = result[0]
            hashed_password = result[1]
            email = result[2]
                    
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
                request.session['secret'] = secret
                request.session['temp_user'] = username

                # set the message to be sent
                message = Mail(
                    from_email='bigbankwebservice@gmail.com',
                    to_emails= email,
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
                error_message = "Invalid Login"
        else:
            error_message = "Invalid Login"
        
        return {
                    "valid_credentials": valid_credentials, 
                    "error_message": error_message
                }
    
    username = request.GET.get('username', None)
    password = request.GET.get('password', None)

    if 'login_query_processed' in request.session:
        if(username and password and not request.session.get('login_query_processed')):
            result = check_credentials(request, username, password)
            error_message = result['error_message']
            valid_credentials = result['valid_credentials']
            page_args = {
                'is_logged_in': ('username' in request.session),
                'error_message' : error_message,
                'valid_credentials' : valid_credentials,
                'username_sendback' : username
            }
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
                'is_logged_in': ('username' in request.session),
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
                request.session['username'] = username
                return home(request) 
            else:
                error_message = "Wrong code"
            
            # make sure the page stays on submit
            valid_credentials = True

    page_args = {
        'is_logged_in': ('username' in request.session),
        'error_message' : error_message,
        'valid_credentials' : valid_credentials,
        'username_sendback' : ''
    }

    username = None
    password = None

    db_connection.commit()
    db_connection.close()

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
    error_message = None  # Initialize values to None or empty string
    username = ''
    firstname = ''
    lastname = ''
    email = ''
    
    if request.method == 'POST':
        username = request.POST['username']
        firstname = request.POST['first-name']
        lastname = request.POST['last-name']
        email = request.POST['email']
        password = request.POST['password']
        password_confirm = request.POST['password_confirm']

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
                params = (uuid.uuid4(), username, email, salt.decode('utf-8'), hashed_password.decode('utf-8'), 0, False)
                cursor.execute(new_item_query, params)
                db_connection.commit()
                db_connection.close()

                # Redirect to a success page or home page
                return home(request)
            else:
                # Passwords don't match, set error message
                error_message = "Confirmed password must match the password."

    page_args = {
        "error_message": error_message,
        'is_logged_in': ('username' in request.session),
        'username_sendback': username,
        'firstname_sendback': firstname,
        'lastname_sendback': lastname,
        'email_sendback': email
    }
    return render(request, "register.html", page_args)

def account(request):
    page_args = {
        'is_logged_in': ('username' in request.session)
    }

    db_connection = connections['default']
    cursor = db_connection.cursor()

    if page_args['is_logged_in']:
        # Populate username
        page_args['username'] = request.session['username']
        
        # get the user
        sql_query = "SELECT id, balance FROM fintech_testbed_app_client WHERE username = %s"
        params = (page_args['username'],)
        cursor.execute(sql_query, params)
        result = cursor.fetchall()
        result = result[0]
        user_id = result[0]
        balance = result[1]

        # get transactions from user account
        sql_query = """
            SELECT t.datetime, t.description, t.sender, t.reciever, t.balance
            FROM fintech_testbed_app_transactions AS t
            JOIN fintech_testbed_app_client AS u ON t.sender = u.username OR t.reciever = u.username
            WHERE u.username = %s;
        """

        params = (page_args['username'],)
        cursor.execute(sql_query, params)
        result = cursor.fetchall()
        transactions = result[:10]

        # Populate balance
        page_args['balance'] = balance #change this to query

        # Populate Recent Transactions
        base_transaction = """
                <span class="date">{}</span>
                <span class="description">{}</span>
                <span class="sender">{}</span>
                <span class="receiver">{}</span>
                <span class="balance">{}</span>"""

        for index, transaction in enumerate(transactions):   
            date,description,sender,receiver,balance =  transaction[0], transaction[1], transaction[2], transaction[3], transaction[4]
            cur_transaction = base_transaction.format(date,description,sender,receiver,balance)
            page_args['transaction'+str(index)] = cur_transaction
            print('transaction'+str(index))
        
        db_connection.commit()
        db_connection.close()
        return render(request, "account.html", page_args)
    else:
        db_connection.commit()
        db_connection.close()
        return render(request, "home.html")

def logout(request):
    if 'username' in request.session:
        del request.session['username']
    return login(request)

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
