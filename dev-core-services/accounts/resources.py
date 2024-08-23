from import_export import resources
from .models import CustomUser, UserProfile
from vendors.models import Vendor
import requests
from django.db import models
from base.resources import BaseResource



class UserProfileResource(BaseResource):
    class Meta:
        model = UserProfile
        fields = BaseResource.COMMON_FIELDS + (
            'user', 'dist', 'state', 'country','zipcode','profile'
        )
