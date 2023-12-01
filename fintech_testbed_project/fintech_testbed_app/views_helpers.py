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
import psycopg2
from urllib.parse import urlencode
from django.urls import reverse
from datetime import datetime

def get_user(username):
    # get the user
    db_connection = connections['default']
    cursor = db_connection.cursor()
    sql_query = "SELECT username, balance, id, email, salt, hashed_password FROM fintech_testbed_app_client WHERE username = %s"
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

def get_admin_user(username):
    # get the user
    db_connection = connections['default']
    cursor = db_connection.cursor()
    sql_query = "SELECT id, username, email, hashed_password, salt FROM fintech_testbed_app_admin WHERE username = %s"
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

def get_flagged_transactions():
    # make database connection
    db_connection = connections['default']
    cursor = db_connection.cursor()

    # get the transactions
    sql_query = "SELECT id, datetime, description, client_username, transactions_id FROM fintech_testbed_app_flagged_transactions"
    cursor.execute(sql_query, )
    result = cursor.fetchall()
    db_connection.commit()
    db_connection.close()
    return result

def get_transaction_by_id(transaction_id):
    # make database connection
    db_connection = connections['default']
    cursor = db_connection.cursor()

    # get the transactions
    sql_query = "SELECT id, balance, datetime, description, reciever, sender FROM fintech_testbed_app_transactions WHERE id = %s"
    params = (transaction_id,)
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

def make_transaction(sender, reciever, value, description, admin):
    db_connection = connections['default']
    cursor = db_connection.cursor()

    try:
        # Begin the transaction
        db_connection.autocommit = False
        new_transactions_query = "INSERT INTO fintech_testbed_app_transactions (id, sender, reciever, balance, datetime, description, admin_cashier) VALUES (%s, %s, %s, %s, %s, %s, %s)"
        params = (uuid.uuid4(), sender, reciever, value, str(datetime.now().strftime('%Y-%m-%d %H:%M:%S')), description, admin)
        cursor.execute(new_transactions_query, params)
        db_connection.commit()
    except psycopg2.Error as e:
        # Rollback the transaction
        db_connection.rollback()
    finally:
        db_connection.close()
    

def undo_transaction(flagged_transaction_id, transaction_id, sender, receiver, value):
    db_connection = connections['default']
    cursor = db_connection.cursor()

    try:
        # update both users account
        db_connection.autocommit = False
        query = "DELETE FROM fintech_testbed_app_flagged_transactions WHERE id = %s"
        param = (str(flagged_transaction_id),)
        cursor.execute(query, param)
        
        
        query = "UPDATE fintech_testbed_app_client SET balance = balance + %s WHERE username = %s"
        sender_params = (value, sender,)
        receiver_params = (value * -1, receiver,)
        cursor.execute(query, sender_params)
        cursor.execute(query, receiver_params)

        # delete transaction
        query = "DELETE FROM fintech_testbed_app_transactions WHERE id = %s"
        deletion_params = (transaction_id,)
        cursor.execute(query, deletion_params)

        db_connection.commit()
    except psycopg2.Error as e:
        # Rollback the transaction
        db_connection.rollback()
    finally:
        db_connection.close()

def delete_flagged_transaction(transaction_id):
    db_connection = connections['default']
    cursor = db_connection.cursor()

    try:
        db_connection.autocommit = False
        query = "DELETE FROM fintech_testbed_app_flagged_transactions WHERE id = %s"
        param = (str(transaction_id),)
        cursor.execute(query, param)
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


def admin_register(username, email, password):
    db_connection = connections['default']
    cursor = db_connection.cursor()

    try:
        db_connection.autocommit = False
    
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
                    
        db_connection = connections['default']
        cursor = db_connection.cursor()

        # Create a new client
        new_item_query = "INSERT INTO fintech_testbed_app_admin (id, username, email, salt, hashed_password) VALUES (%s, %s, %s, %s, %s)"
        params = (uuid.uuid4(), username, email, salt.decode('utf-8'), hashed_password.decode('utf-8'))
        cursor.execute(new_item_query, params)
        db_connection.commit()
    except psycopg2.Error as e:
        # Rollback the transaction
        db_connection.rollback()
    finally:
        db_connection.close()

def admin_all_select():
    # make database connection
    db_connection = connections['default']
    cursor = db_connection.cursor()

    # get the transactions
    sql_query = "SELECT id, username, email, salt, hashed_password FROM fintech_testbed_app_admin"
    cursor.execute(sql_query, )
    result = cursor.fetchall()
    db_connection.commit()
    db_connection.close()

    if result:
        result = result[0]
        return result
    else:
        return None
