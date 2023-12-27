from django.db import models
from django.contrib.auth.models import AbstractBaseUser,BaseUserManager
# Create your models here.

class UserManager(BaseUserManager):
    def get_by_natural_key(self, email):
        return self.get(email=email)
    
class User(AbstractBaseUser):
    objects = UserManager()
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=512)
    USERNAME_FIELD = 'email'
    clientKey = models.CharField(max_length = 512)

