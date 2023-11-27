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