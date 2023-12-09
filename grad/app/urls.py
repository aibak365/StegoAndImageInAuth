from django.urls import path
from app import views

urlpatterns = [
    path('register', views.register, name='register'),
    path('log_in', views.log_in, name="log_in"),
    path('', views.index, name="index"),
    path('hello',views.hello, name='hello')
]