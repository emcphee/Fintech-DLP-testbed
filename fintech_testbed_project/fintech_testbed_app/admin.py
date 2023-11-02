from django.contrib import admin

# Register your models here.
from .models import Admin, Client, BankAccount, Transactions

admin.site.register(Admin)
admin.site.register(Client)
admin.site.register(BankAccount)
admin.site.register(Transactions)
