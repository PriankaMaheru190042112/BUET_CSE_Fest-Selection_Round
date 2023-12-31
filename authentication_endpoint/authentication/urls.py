from django.contrib import admin
from django.urls import include, path
from .views import *

urlpatterns = [
    path('', index, name='index'),
    path('signup/', SignUpView.as_view(), name='signup'),
    path('login', LoginView.as_view(), name='login'),
]
