from django.db.models.signals import post_save
from django.dispatch import receiver
from allauth.account.models import EmailAddress
from accounts.models import CustomUser, UserProfile
from vendors.models import Vendor
from django.contrib.auth import get_user_model
from django.utils.text import slugify
import uuid
from rest_framework import serializers
import random
from django_otp.plugins.otp_totp.models import TOTPDevice
from django.db.models.signals import pre_save
from django.dispatch import receiver
from base.functions import get_auto_id


# def create_user_profile_if_not_exists(instance):
#     """
#     Creates a user profile for the given instance if it doesn't already exist.
#     """
#     if not UserProfile.objects.filter(user=instance).exists():
        

@receiver(post_save, sender=get_user_model())
def add_name_to_profiles(sender, instance, created, company_name='', **kwargs):

    existing_totp_device = TOTPDevice.objects.filter(user=instance, confirmed=False).first()
   
    if created :  
        existing_profile = UserProfile.objects.filter(user=instance).first() 
        if existing_profile:
            # If a profile already exists, print a message indicating it
            print("UserProfile already exists.")
        else:
            # If no profile exists, create a new one
            auto_id = get_auto_id(UserProfile)
            print("The auto id is", auto_id)
            user_profile = UserProfile.objects.create(user=instance, auto_id=auto_id, created_by=instance)
            print('UserProfile Saved..!')
               
        if instance.role == get_user_model().CUSTOMER:

            
            if not existing_totp_device:
                # TOTPDevice does not exist, create a new one
                totp_device = TOTPDevice.objects.create(user=instance, confirmed=False)
                totp_device.save()
                print('New TOTPDevice created')
            else:
                # TOTPDevice already exists, do something else or just pass
                print('TOTPDevice already exists')
            
            print('Got in to customer role in signals')

            
                               
            # If the user has the role of 'Vendor' 
        elif instance.role == get_user_model().VENDOR:

            print("iN SIGNALS COMPANY NAME IS ",company_name)

            if not existing_totp_device:
                # TOTPDevice does not exist, create a new one
                totp_device = TOTPDevice.objects.create(user=instance, confirmed=False)
                totp_device.save()
                print('New TOTPDevice created')
            else:
                # TOTPDevice already exists, do something else or just pass
                print('TOTPDevice already exists')
            
            # Create user profile if not exists
            # create_user_profile_if_not_exists(instance)
            
           
                
             
            vendor_profile, _ = Vendor.objects.get_or_create(user=instance)
            vendor_profile.name = company_name
            random_number = random.randint(1, 9999)
            vendor_profile.slug = f"{slugify(instance.username)}-{random_number}" #Using a random string as slug
            vendor_profile.save()

            
            
