from django.contrib import admin

# Register your models here.
from .models import Admin, Client, Transactions, Cashier

admin.site.register(Admin)
admin.site.register(Client)
admin.site.register(Cashier)
admin.site.register(Transactions)
