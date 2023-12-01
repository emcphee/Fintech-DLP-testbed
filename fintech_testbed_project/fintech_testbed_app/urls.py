from django.urls import path
from . import views

urlpatterns = [
    path('home/', views.home, name='home'),
    path('', views.home),
    path('login/', views.login, name='login'),
    path('admin-login/', views.admin_login, name='admin-login'),
    path('logout/', views.logout, name='logout'),
    path('aboutus/', views.aboutus),
    path('services/', views.services),
    path('contactus/', views.contactus),
    path('register/', views.register, name='register'),
    path('account/', views.account, name='account'),
    path('cashier/', views.cashier, name='cashier'),
    path('transfer/', views.transfer, name='transfer'),
    path('flagged-transactions/', views.flagged_transaction, name='flagged-transfer'),
    path('check_login_status/', views.check_login_status, name='checkLoginStatus'),
]
