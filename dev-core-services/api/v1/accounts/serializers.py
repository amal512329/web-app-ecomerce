from dj_rest_auth.registration.serializers import RegisterSerializer
from dj_rest_auth.registration.serializers import RegisterSerializer
from rest_framework.response import Response
from rest_framework import status
from allauth.account.models import EmailAddress
from allauth.account.utils import send_email_confirmation
from accounts.models import CustomUser
from allauth.account.adapter import get_adapter
from vendors.models import Vendor
from rest_framework import serializers
from .signals import add_name_to_profiles
from dj_rest_auth.serializers import LoginSerializer
from rest_framework.authtoken.models import Token
from django_otp.plugins.otp_totp.models import TOTPDevice
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer



class CustomUserRegistrationSerializer(RegisterSerializer):
    
    ROLE_CHOICES = [
        (1, 'Customer'),
        (2, 'Vendor'),
    ]
    
    
    first_name = serializers.CharField(max_length=30, required=True)
    last_name = serializers.CharField(max_length=30, required=True)
    role = serializers.ChoiceField(choices=ROLE_CHOICES, default=2)
    company_name = serializers.CharField(required=False)
   
   
   
    def get_cleaned_data(self):
        data_dict = super().get_cleaned_data()
        data_dict['role'] = self.validated_data.get('role', 2)
        return data_dict
    

    

    def save(self, request):
        
        adapter = get_adapter()
        user = adapter.new_user(request)
        self.cleaned_data = self.get_cleaned_data()
        company_name = request.data.get('company_name', '')

        role_mapping = {1: CustomUser.CUSTOMER, 2: CustomUser.VENDOR}
        selected_role = self.cleaned_data.get('role', 2)
      

        

        
        if selected_role == 1 or selected_role == 2:
            user.role = role_mapping[selected_role]
        
            print(user.role,'In serializer')
           
            if selected_role == 2:
               
               print("SELECTED ROLE IS VENDOR")

               if not company_name:
                    raise serializers.ValidationError({"company_name": "Company name is required for Vendor."})
              
                # Print the value of company_name before saving
               print("Company Name:", company_name)
               
        
        else:
            # Set a default role if the selected role is not recognized
            user.role = CustomUser.VENDOR
           

        adapter.save_user(request, user, self)

        self.custom_signup(request, user)
         
        add_name_to_profiles(sender=CustomUser, instance=user, created=True, company_name=company_name)

        print('In serializer the user is',user.role)
        return user


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):

 
    otp_code = serializers.CharField(write_only=True, required=False)

    def validate(self, attrs):
        otp_code = attrs.get('otp_code', None)

        # Call the base class's validate method to get the token data
        data = super().validate(attrs)

        # If there's an OTP code, validate it
        if otp_code:
            user = self.user

            # Check if the user has an active TOTP device
            totp_device = TOTPDevice.objects.filter(user=user, confirmed=True).first()

            if totp_device and totp_device.verify_token(otp_code):
                # Valid OTP code, return the token data
                return data
            else:
                raise serializers.ValidationError({'otp_code': 'Invalid OTP code'})
        else:
            # No OTP code provided, raise an error
            raise serializers.ValidationError({'otp_code': 'This field is required when using TOTP'})



class CustomLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):
        # Custom validation logic for the password
        password = data.get('password', None)

        if not password:
            raise serializers.ValidationError('Password is required.')
        # Add your own password validation criteria here
        if len(password) < 8:
            raise serializers.ValidationError('Password must be at least 8 characters long.')
        # You can add more validation criteria as needed
        return data


class LoginResponseSerializer(serializers.Serializer):
    access_token = serializers.CharField()
    refresh_token = serializers.CharField()
    user_id = serializers.IntegerField() 