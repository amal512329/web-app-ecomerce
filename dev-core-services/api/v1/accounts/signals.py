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





@receiver(post_save, sender=get_user_model())
def add_name_to_profiles(sender, instance, created, company_name='',**kwargs):

    existing_totp_device = TOTPDevice.objects.filter(user=instance, confirmed=False).first()
   
    if created:  
    
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
            user_profile, _ = UserProfile.objects.get_or_create(user=instance)
            user_profile.save()


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


            
            user_profile, _ = UserProfile.objects.get_or_create(user=instance)
            user_profile.save()    
            vendor_profile, _ = Vendor.objects.get_or_create(user=instance)
            vendor_profile.name = company_name
            random_number = random.randint(1, 9999)
            vendor_profile.slug = f"{slugify(instance.username)}-{random_number}" #Using a random string as slug
            vendor_profile.save()

            


            
            
