from django.db import models
from django.contrib.auth.models import AbstractUser,BaseUserManager
from versatileimagefield.fields import VersatileImageField,PPOIField
from base.models import BaseModel
import uuid
from django.utils import timezone
import datetime
from django.core.mail import EmailMultiAlternatives
from django.dispatch import receiver
from django.template.loader import render_to_string
from django.urls import reverse
from django.core.mail import send_mail
from django_rest_passwordreset.signals import reset_password_token_created


class MyUserManager(BaseUserManager):

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
   
    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
      

        return self.create_user(email, password, **extra_fields)



# Create your models here.
class CustomUser(AbstractUser):
    
    CUSTOMER = 1
    VENDOR = 2

    ROLE_CHOICES = (
        (CUSTOMER, 'Customer'),
        (VENDOR, 'Vendor'),
    )

    # api/v1/accounts/serializers, urls, signal, tasks, views
    # api/v1/vendors/serializers, urls, signal, tasks, views
    
    id = models.UUIDField(primary_key=True,default=uuid.uuid4, editable=False)
    username = models.CharField(max_length=150, unique=True, verbose_name='Username')
    firstname = models.CharField(max_length=30, verbose_name='First Name')
    lastname = models.CharField(max_length=30, verbose_name='Last Name')
    email = models.EmailField(unique=True, verbose_name='Email')
    phone = models.CharField(max_length=15, verbose_name='Phone')
    password = models.CharField(max_length=128, verbose_name='Password')
    role = models.PositiveSmallIntegerField(choices=ROLE_CHOICES, null=True, verbose_name='Role')
   
    is_active_2fa = models.BooleanField(default=False, verbose_name='Is_Active_2FA')
    date_joined = models.DateTimeField(auto_now_add=True, verbose_name='Date Joined')
    last_login = models.DateTimeField(auto_now_add=True, verbose_name='Last Login')
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='Created At')
    updated_at = models.DateTimeField(auto_now=True, verbose_name='Updated At')
    is_admin = models.BooleanField(default=False, verbose_name='Is Admin')
    is_staff = models.BooleanField(default=False, verbose_name='Is Staff')
    is_superadmin = models.BooleanField(default=False, verbose_name='Is Superadmin')
    is_active = models.BooleanField(default=True, verbose_name='Is Active')
    is_deleted = models.BooleanField(default=False, verbose_name='Is Deleted')

    objects = MyUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username'] 


    @property
    def display_role(self):
        """
        Returns the display value of the user's role.
        """
        for role_id, role_name in self.ROLE_CHOICES:
            if self.role == role_id:
                return role_name
        return None
    

    class Meta:

        db_table = "core_customuser"
        verbose_name = 'Custom User'
        verbose_name_plural = 'Custom Users'
        ordering = ('created_at',)

    def __str__(self):
        return self.username


class UserProfile(BaseModel):
  
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='profile')
    address1 = models.CharField(max_length=255, blank=True, verbose_name='Address 1')
    address2 = models.CharField(max_length=255, blank=True, verbose_name='Address 2')
    address3 = models.CharField(max_length=255, blank=True, verbose_name='Address 3')
    dist = models.CharField(max_length=100, blank=True, verbose_name='District')
    state = models.CharField(max_length=100, blank=True, verbose_name='State')
    country = models.CharField(max_length=100, blank=True, verbose_name='Country')
    zip_code = models.CharField(max_length=20, blank=True, verbose_name='ZIP Code')
    profile = VersatileImageField(upload_to='profile_pics/', blank=True, verbose_name='Profile Picture')
    profile_ppoi = PPOIField()
    cover = VersatileImageField(upload_to='cover_pics/', blank=True, verbose_name='Cover Picture') 
    

@receiver(reset_password_token_created)
def password_reset_token_created(sender,instance,reset_password_token,*args,**kwargs):
    
    email_plaintext_message = "{}?token={}".format(
            instance.request.build_absolute_uri(reverse('password_reset:reset-password-confirm')),
            reset_password_token.key)
    
    send_mail(
        
        # title:
        "Password Reset for {title}".format(title="Your Website Title"),

        # message:
        email_plaintext_message,

        # from:
        "amaldq333@gmail.com",
        # to:
        [reset_password_token.user.email]


    )