from django.db import models
import uuid

class Cashier(models.Model):
    id = models.UUIDField(
        primary_key=True, 
        default=uuid.uuid4,
        help_text = 'Unique ID for the admin'
    )
    
    username = models.CharField(
        max_length=100, 
        help_text='Enter a admin username'
    )

    email = models.CharField(
        max_length=100,
        help_text='Enter a client email'

    )

    salt = models.CharField(
        max_length=100,
        default=None,
        help_text='Enter a salt'
    )

    hashed_password = models.CharField(
        max_length=100,
        default=None,
        help_text='Enter a hash'
    )

    def __str__(self):
        """String for representing the Model object."""
        return f'{self.id}'

class Admin(models.Model):
    id = models.UUIDField(
        primary_key=True, 
        default=uuid.uuid4,
        help_text = 'Unique ID for the admin'
    )
    
    username = models.CharField(
        max_length=100, 
        help_text='Enter a admin username',
        unique=True
    )

    email = models.CharField(
        max_length=100,
        help_text='Enter a client email'

    )

    salt = models.CharField(
        max_length=100,
        default=None,
        help_text='Enter a salt'
    )

    hashed_password = models.CharField(
        max_length=100,
        default=None,
        help_text='Enter a hash'
    )

    def __str__(self):
        """String for representing the Model object."""
        return f'{self.id}'

class Client(models.Model):
    id = models.UUIDField(
        primary_key=True, 
        default=uuid.uuid4,
        help_text = 'Unique ID for the client'
    )
    
    username = models.CharField(
        max_length=100, 
        help_text='Enter a client username',
        unique=True
    )

    email = models.CharField(
        max_length=100,
        help_text='Enter a client email'
    )

    salt = models.CharField(
        max_length=100,
        default=None,
        help_text='Enter a salt'
    )

    hashed_password = models.CharField(
        max_length=100,
        default=None,
        help_text='Enter a hash'
    )

    balance = models.FloatField(default=0)

    is_business = models.BooleanField(default=False)

    def __str__(self):
        """String for representing the Model object."""
        return f'{self.id}'


class Transactions(models.Model):
    id = models.UUIDField(
        primary_key=True, 
        default=uuid.uuid4,
        help_text = 'Unique ID for the transactions'
    )

    # Account sending money
    sender = models.ForeignKey(
        Client,
        on_delete=models.CASCADE,
        related_name='sent_transactions', 
        null=True,
        default=None,
        to_field='username',
        db_column='sender',
        help_text = 'The username of the client'
    )

    # Account recieving money
    reciever = models.ForeignKey(
        Client,
        on_delete=models.CASCADE,
        related_name='received_transactions',
        null=True,
        default=None,
        to_field='username',
        db_column='reciever',
        help_text = 'The username of the client'
    )

    # used if an admin is in control of a transaction
    admin_cashier = models.ForeignKey(
        Admin,
        on_delete=models.CASCADE,
        related_name='admin_control',
        null=True,
        default=None,
        to_field='username',
        db_column='admin_cashier',
        help_text = 'The username of the admin'
    )

    balance = models.FloatField()
    datetime = models.CharField(max_length=30)
    description = models.CharField(max_length=30)

    def __str__(self):
        """String for representing the Model object."""
        return f'{self.id}'

class Flagged_Transactions(models.Model):
    id = models.UUIDField(
        primary_key=True, 
        default=uuid.uuid4,
        help_text = 'Unique ID for the transactions'
    )

    Transactions_ID = models.ForeignKey(
        Transactions,
        on_delete=models.CASCADE,
        default=None,
        db_column='transactions_id',
        help_text = 'The ID of the transaction'
    )

    Client_Username = models.ForeignKey(
        Client,
        on_delete=models.CASCADE,
        default=None,
        to_field='username',
        db_column='client_username',
        help_text = 'The ID of the client'
    )

    description = models.CharField(max_length=5000)
    datetime = models.CharField(max_length=30)

    def __str__(self):
        """String for representing the Model object."""
        return f'{self.id}'
