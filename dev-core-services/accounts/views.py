from django.shortcuts import render,redirect
from accounts.serializers import (CustomUserRegistrationSerializer,CustomTokenObtainPairSerializer,CustomUserSocialRegistrationSerializer,
CustomLoginSerializer,VendorDetailsSerializer,UserProfileSerializer)
from dj_rest_auth.registration.views import RegisterView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from allauth.account.utils import send_email_confirmation
from allauth.account.models import EmailAddress
from rest_framework import status,generics
from rest_framework.views import APIView
import requests
from vendors.models import Vendor
from dj_rest_auth.views import LoginView as RestAuthLoginView
from base64 import b64encode
from rest_framework_simplejwt.tokens import AccessToken,RefreshToken
from django_otp.plugins.otp_totp.models import TOTPDevice
from rest_framework.authtoken.models import Token
import qrcode
from io import BytesIO
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth import authenticate,login
from decouple import config
from .serializers import SocialLoginFrontendDataSerializer,VendorDetailsSerializer,ChangePasswordSerializer
import secrets
import string
import random
#finish and redirecting view
from django.views import View
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.contrib.auth import get_user_model
from django.http import HttpResponseNotFound,JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.permissions import IsAuthenticated,AllowAny
UserModel = get_user_model()
from .models import CustomUser
from google.oauth2 import id_token
from google.auth.transport import requests as googlerequest
from allauth.socialaccount.models import SocialToken, SocialAccount, SocialApp
import requests
from accounts.models import UserProfile
from rest_framework.parsers import JSONParser
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError


# Create your views here.


class CustomUserRegistrationView(RegisterView):
    
    permission_classes = [AllowAny]
    serializer_class = CustomUserRegistrationSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        role_str = serializer.validated_data.get('role')
        role_mapping = {'CUSTOMER': 1, 'VENDOR': 2}
        role_numeric = role_mapping.get(role_str) 

        print(role_numeric, 'in view')

        user = self.perform_create(serializer, role_numeric)
        user.role = role_str
        user.firstname = request.data.get('first_name', '')
        user.lastname = request.data.get('last_name', '')
        print('IN VIEWS THE LASTNAME IS :', user.lastname)
        user.save()

        print("User role saved in customuser")

        email_address, created = EmailAddress.objects.get_or_create(
            user=user,
            email=user.email,
            defaults={'primary': False}
        )

        if not created:
            # If the EmailAddress already exists, update the primary field
            email_address.primary = False
            email_address.save()
       
        # Send email confirmation
        send_email_confirmation(request, user)

        return Response({'detail': 'Registration successful. An email has been sent for verification.'}, status=status.HTTP_201_CREATED)
        
    def perform_create(self, serializer, role_numeric):
        user = serializer.save(self.request)
        user.role = role_numeric  # Set the numeric role value
        print(user.role, 'During serializer')
        user.save()
        print(user, 'During perform_create')   
        return user


  

class CustomEmailConfirmView(APIView):

    
    def get(self, request, key): 
        
        verify_email_url = 'http://127.0.0.1:8000/dj-rest-auth/registration/verify-email/'
      
       # Make a POST request to the verify-email endpoint with the key
        response = requests.post(verify_email_url, data={'key': key})

        if response.status_code == 200:

            print("Custom email confirmed")
             # Assuming 'custom-login' is the name of your custom login URL
            return redirect('http://127.0.0.1:8000/api/v1/user/login')
        else:
            return Response({'message': 'Email verification failed'}, status=status.HTTP_400_BAD_REQUEST)
    

#custom login 
              
class CustomLoginView(RestAuthLoginView):
    
   
    def post(self, request, *args, **kwargs):
                
        print("test 1: ", request.data)
        serializer_class = CustomLoginSerializer(data=request.data)
        print("After social Serialization")
        if serializer_class.is_valid(raise_exception=True):
            # Access validated data using serializer.validated_data
            email = serializer_class.validated_data['email']
            password = serializer_class.validated_data['password']
            # Your authentication logic here
            user = authenticate(request, email=email, password=password)
            
            if user is not None:
                # Generate or retrieve the authentication token
                print("In to the access_token")
                access_token = AccessToken.for_user(user)   
               
                # Generate or retrieve the refresh token
                refresh_token = RefreshToken.for_user(user)
                # Get the user's TOTP device
                totp_device = TOTPDevice.objects.filter(user=user).first()

                if totp_device:                   
                   # Generate QR code
                    qr_code_img = qrcode.make(totp_device.config_url)
                    buffer = BytesIO()
                    qr_code_img.save(buffer)
                    buffer.seek(0)
                    encoded_img = b64encode(buffer.read()).decode()
                    qr_code_data = f'data:image/png;base64,{encoded_img}'
                    user_id_str = str(user.id)
                    first_name = str(user.firstname)
                    last_name = str(user.lastname)
                    phone = str(user.phone)
                    role = str(user.display_role)
                    is_active_2fa = str(user.is_active_2fa)
                    date_joined = str(user.date_joined)
                    

                    access_token_data = {
                        "qr": qr_code_data,
                        "username": user.username,
                        'user_id':user_id_str,
                        "first_name":first_name,
                        "last_name":last_name,
                        "phone":phone,
                        "role":role,
                        "is_active_2FA":is_active_2fa,
                        "date_joined":date_joined
                       
                    }          
                    access_token = AccessToken.for_user(user)
                    removed_item = access_token.payload.pop('user_id',None)
                    access_token.payload.update(access_token_data)

                    print('Removed Item :',removed_item)
                    # Return the JWT access token
                    return Response({'access_token': str(access_token),'refresh_token': str(refresh_token)} ,status=status.HTTP_200_OK)
                    # return render(request, 'qrcode.html', {'qr_code_data': qr_code_data, 'username': user.username, 'user_id': user.id})
                else:
                    return Response({'message': 'User has no TOTP device'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'message': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            # Handle validation errors
            return Response(serializer_class.errors, status=status.HTTP_400_BAD_REQUEST)

    def generate_qr_code(self, totp_url):
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
     
        )
        qr.add_data(totp_url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer)
        # qr_code_image = base64.b64encode(buffer.getvalue()).decode()
        encoded_img = b64encode(buffer.read()).decode()
        qr_code_data = f'data:image/png;base64,{encoded_img}'

        print("QR CODE is printing")

        print(qr_code_data)

        return qr_code_data
        
    
    
# @method_decorator(csrf_exempt, name='dispatch')
# @permission_classes([IsAuthenticated])
class FinishAndRedirectView(APIView):
   
    def post(self, request, *args, **kwargs):
        # Retrieve the access token from the Authorization header
        authorization_header = request.headers.get('Authorization')
        
        if not authorization_header or not authorization_header.startswith('Bearer '):
            return Response({'error': 'Invalid or missing access token'}, status=status.HTTP_401_UNAUTHORIZED)

        access_token_str = authorization_header.split('Bearer ')[1].strip()
        print(access_token_str)
        access_token = AccessToken(access_token_str)

        username = access_token.payload.get('username')
        user_id = access_token.payload.get('id')

        user = UserModel.objects.get(id=user_id, username=username)

        totp_device = TOTPDevice.objects.filter(user=user).first()
        print(totp_device)

        if totp_device:
            # Confirm the TOTP device
            print("Hey confirmed ")
            totp_device.confirmed = True
            totp_device.save()

            user.is_active_2fa =True
            user.save()
            # Redirect to API token endpoint or any other desired URL
            # Update with your actual URL pattern name
            return Response({'message': 'OTP SUCCESS'}, status=status.HTTP_200_OK)
        else:
            return  Response({'message': 'OTP FAILED'}, status=status.HTTP_401_UNAUTHORIZED)



class CustomTokenObtainPairView(TokenObtainPairView):
    
    serializer_class = CustomTokenObtainPairSerializer
    
    def post(self, request, *args, **kwargs):
       
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # If the serializer is valid, return the token data
            return Response(serializer.validated_data, status=status.HTTP_200_OK)
        else:
            # If the serializer is not valid, return the validation errors
            return Response(serializer.errors, status=status.HTTP_402_PAYMENT_REQUIRED)
        

class SkipAndLogin(APIView):

    def post(self, request, *args, **kwargs):
        # Your existing authentication logic
        authorization_header = request.headers.get('Authorization')
        
        if not authorization_header or not authorization_header.startswith('Bearer '):
            return Response({'error': 'Invalid or missing access token'}, status=status.HTTP_401_UNAUTHORIZED)
    
        access_token_str = authorization_header.split('Bearer ')[1].strip()
        print(access_token_str)
    
       # Decode the access token
        try:
            access_token = AccessToken(access_token_str)
        except Exception as e:
            return Response({'error': 'Invalid access token'}, status=status.HTTP_401_UNAUTHORIZED)

        # Generate a new refresh token
        # refresh = RefreshToken.for_user(access_token.payload.get('username'))

        # Create a DRF response with access token and refresh token
        response_data = {
            'access_token': str(access_token),
            # 'refresh_token': str(refresh),
        }
        return Response(response_data, status=status.HTTP_200_OK)



class SocialLoginVerificationView(APIView):
    
    
    def post(self,request, *args, **kwargs):
           
        try:
       # Validate and extract data from the frontend
            frontend_data = SocialLoginFrontendDataSerializer(data=request.data)
            if frontend_data.is_valid():

                id_token_val = request.data.get('idToken')
                audience = config('GOOGLE_CLIENT_ID'),  # Client ID
                decoded_token = decode_google_token(id_token_val, audience)
                names = request.data.get('name')              
            
                if decoded_token:
                   
                    if (
                        decoded_token.get('sub') == request.data.get('id') and
                        decoded_token.get('email') == request.data.get('email') and
                        decoded_token.get('email_verified') == True
                    ):
                        # Check if the user already exists in the database
                        user_exists = SocialAccount.objects.filter(
                            uid=request.data.get('id'),
                            provider=request.data.get('provider'),
                        ).exists()

                        if not user_exists: 
                            user_name = request.data.get('name')
                            user_email = request.data.get('email')
                            
                            random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
                            password = f"{user_name.lower()}_{random_string}"   
                             # Remove spaces from the password
                            generated_password = password.replace(" ", "")
                            user_password  = generated_password   
                           
                            serializer = CustomUserSocialRegistrationSerializer(data={
                                
                                'username':request.data.get('name'),
                                'email': request.data.get('email'),
                                'firstname': request.data.get('firstName'),
                                'lastname': request.data.get('last_name'),
                                'password':user_password,
                                # Add other fields as needed
                            })

                            if serializer.is_valid():

                                user = self.perform_create(serializer)
                               # Additional field   
                                user.firstname = request.data.get('firstName', '')  
                                user.save()
                                email = request.data.get('email')

                            social_account = SocialAccount.objects.create(
                                user=user,
                                provider=request.data.get('provider'),
                                uid=request.data.get('id'),
                                extra_data={
                                    'id_token': request.data.get('idToken'),
                                    'id': request.data.get('id'),
                                    'name': request.data.get('name'),
                                    'email': request.data.get('email'),
                                    'photoUrl': request.data.get('photoUrl'),
                                    'first_name': request.data.get('firstName'),
                                    'provider': request.data.get('provider')
                                }
                            )
                            email_address = EmailAddress.objects.create(
                            user=user,
                            email=request.data.get('email'),
                           verified=True ,primary=True # Set to True if the email is already verified
)                           
                            email_address.save()
                 
                            # Retrieve the first SocialApp instance or None if there are no instances
                            first_social_app = SocialApp.objects.first()

                            if first_social_app:
                                 # Attempt to retrieve an existing SocialToken
                                social_token, created = SocialToken.objects.get_or_create(
                                app=first_social_app,
                                account=social_account,
                                defaults={'token': id_token_val}
    )

                                 # If the SocialToken was created, you may want to update its token
                                if created:
                                    social_token.token = id_token_val
                                    social_token.save()
                                                           
                                # Check if login was successful
                                user = authenticate(request, email=email, password=user_password)
            
                                if user is not None:
                                    # Generate or retrieve the authentication token
                                    print("In to the access_token")
                                    user_id_str = str(user.id)
                                    access_token_data = {                              
                                    "username": user.username,
                                    'id':user_id_str
                                                   }          
                                    access_token = AccessToken.for_user(user)
                                    refresh_token = RefreshToken.for_user(user)
                                    removed_item = access_token.payload.pop('user_id',None)
                                    access_token.payload.update(access_token_data)
                                    # Return the JWT access token
                                    return Response({'access_token': str(access_token),'refresh_token': str(refresh_token)} ,status=status.HTTP_200_OK)
                                return Response({'error': 'No SocialApplication instances found'}, status=status.HTTP_404_NOT_FOUND)

                        else:
                           # Log in the existing user
                            user_name = request.data.get('name')
                            user_email = request.data.get('email') 
                            user = CustomUser.objects.get(email=user_email)
                                                                                  
                            if user is not None:
                                login(request,user)
                                user_id_str = str(user.id)
                                access_token_data = {                              
                                "username": user.username,
                                'id':user_id_str
                                                   }          
                                access_token = AccessToken.for_user(user)
                                refresh_token = RefreshToken.for_user(user)
                                removed_item = access_token.payload.pop('user_id',None)
                                access_token.payload.update(access_token_data)
                                # Return the JWT access token
                                return Response({'access_token': str(access_token),'refresh_token': str(refresh_token)} ,status=status.HTTP_200_OK)
                            else:
                                # Handle the case where authentication fails (this might not happen if the user already exists)
                                return Response({'error': 'Authentication failed'}, status=status.HTTP_400_BAD_REQUEST)
                
                else:
                    # Add a response for the case where the verification fails
                    return Response({'error': 'Verification failed'}, status=status.HTTP_400_BAD_REQUEST)

            else:
                # frontend_data is not valid
                return Response({'error': 'Invalid data provided'}, status=status.HTTP_400_BAD_REQUEST)

        except ValueError as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'error': 'Data mismatch between ID token and frontend data'}, status=status.HTTP_400_BAD_REQUEST)

    def perform_create(self,serializer):
        user = serializer.save()
        user.save()
        print(user, 'During perform_create')   
        return user


def decode_google_token(id_token_val, client_id_val):
    try:
        req = googlerequest.Request()
        info = id_token.verify_oauth2_token(id_token=id_token_val, request=req, audience=client_id_val)
        print("result info: : : ", info)
        return info
    except ValueError as e:
        print("error: : : ", e)
        raise ValueError('Failed to decode Google ID token')
    

from django.shortcuts import get_object_or_404
from django.utils.translation import gettext 
from django.utils.translation import activate, deactivate
from googletrans import Translator
from rest_framework.decorators import parser_classes
from rest_framework.parsers import JSONParser


class VendorDetailsAPIView(generics.RetrieveAPIView):
   
    serializer_class = VendorDetailsSerializer

    def get_queryset(self):
        user_model = get_user_model()
        return user_model.objects.filter(id=self.kwargs['uuid'])

    def get_translated_data(self, serializer_data, dest_language):
        translated_data = {}
        translator = Translator()
        for key, value in serializer_data.items():
            if isinstance(value, str):
                translated_value = translator.translate(value, dest=dest_language).text
                translated_data[key] = translated_value if translated_value is not None else 'blank'
            elif isinstance(value, str):  # Translate string values
                translated_data[key] = translator.translate(value, dest=dest_language).text
            else:
                translated_data[key] = 'blank' if value is None else value
        return translated_data

    def get(self, request, *args, **kwargs):
        queryset = self.get_queryset()

        if queryset.exists():
            user = queryset.first()
            vendor = Vendor.objects.filter(user=user).first()

            if vendor:
                user_profile_data, created = UserProfile.objects.get_or_create(user=user)
                serializer_data = {
                    'address1': str(user_profile_data.address1),
                    'address2': str(user_profile_data.address2),
                    'address3': str(user_profile_data.address3),
                    'dist': str(user_profile_data.dist),
                    'state': str(user_profile_data.state),
                    'country': str(user_profile_data.country),
                    'zip_code': str(user_profile_data.zip_code),
                    'company_name': vendor.name,
                    'id': self.kwargs['uuid']
                }
                
                for key,value in serializer_data.items():
                    if value == '':
                        serializer_data[key] = 'null'

               
                # Ensure any None values are also replaced with 'null'
                serializer_data = {key: 'null' if value is None else value for key, value in serializer_data.items()}

                # Get the language from the request header, defaulting to 'en' (English)
                translated_language = request.query_params.get('lang','en')

                # Translate the data based on the language
                translated_data = self.get_translated_data(serializer_data, translated_language)

                if translated_data is not None:
                    return JsonResponse(translated_data)
                else:
                    return Response({'detail': _('Failed to translate data.')}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                return Response({'detail': _('Vendor details not found for this user.')}, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'detail': _('User not found with the provided UUID.')}, status=status.HTTP_404_NOT_FOUND)
    

    def post(self, request, uuid):
        
        user_profile_data, created = UserProfile.objects.get_or_create(user_id=uuid)
        print('The UUID is',uuid)
        # Extract address and place data from the request body
        address = request.data.get('address', '')
        place = request.data.get('place', '')

        # Create the 'user' key with the user ID
        print('The adress is ,',address)
        data = {
         
            'address': address,
            'place': place
        }

        # Translate the serialized data
        translated_language = request.headers.get('Language','en')
        translated_data = self.get_translated_data(data, translated_language)

        response_data = {
            'status': 'success',
            'message': 'Data translated successfully',
            'translated_data': translated_data
        }

        return JsonResponse(response_data, status=status.HTTP_201_CREATED)
    

from rest_framework import exceptions
from rest_framework_simplejwt.tokens import Token


class ResetPasswordAPIView(APIView):
    
    serializer_class = ChangePasswordSerializer
    permission_classes = [IsAuthenticated]
  
    def post(self, request, *args, **kwargs):
        authorization_header = request.headers.get('Authorization')
        print("Hello mannn")
        
        if not authorization_header or not authorization_header.startswith('Bearer '):
            return Response({'error': 'Invalid or missing access token'}, status=status.HTTP_204_NO_CONTENT)

        access_token_str = authorization_header.split('Bearer ')[1].strip()

        print("ACCESTOKEN :",access_token_str)
        access_token = AccessToken(access_token_str)

        username = access_token.payload.get('username')
        user_id = access_token.payload.get('user_id')
        print("the user_id is",user_id)

        
        try:
            # Retrieve the user object from the database
            user = UserModel.objects.get(id=user_id, username=username)
        except UserModel.DoesNotExist:
            return Response({'error': 'User does not exist'}, status=status.HTTP_404_NOT_FOUND)


        # Now you have the user object, you can proceed with the password reset logic
        
        serializer = self.serializer_class(data=request.data)
        
        if serializer.is_valid():
            # Check if old password is correct
            if not user.check_password(serializer.validated_data.get('old_password')):
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            
            # Set new password and save user
            user.set_password(serializer.validated_data.get("new_password"))
            user.save()

            response = {
                "status": "Success",
                "code": status.HTTP_200_OK,
                "message": "Password Updated Successfully"
            }

            return Response(response)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)