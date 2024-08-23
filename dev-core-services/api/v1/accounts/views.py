from django.shortcuts import render,redirect
from accounts.serializers import (CustomUserRegistrationSerializer,CustomTokenObtainPairSerializer,
CustomLoginSerializer,LoginResponseSerializer)
from dj_rest_auth.registration.views import RegisterView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from allauth.account.utils import send_email_confirmation
from allauth.account.models import EmailAddress
from rest_framework import status
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
from rest_framework.renderers import JSONRenderer
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.decorators import renderer_classes
from rest_framework.renderers import JSONRenderer

#finish and redirecting view

from django.views import View
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.contrib.auth import get_user_model
from django.http import HttpResponseNotFound
from django.views.decorators.csrf import csrf_exempt
from rest_framework.permissions import IsAuthenticated,AllowAny
UserModel = get_user_model()


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
        
        verify_email_url = 'https://75ad-103-203-73-79.ngrok-free.app/dj-rest-auth/registration/verify-email/'
       # Make a POST request to the verify-email endpoint with the key
        response = requests.post(verify_email_url, {'key': key})

        if response.status_code == 200:

            print("Custom email confirmed")
             # Assuming 'custom-login' is the name of your custom login URL
            return redirect('http://127.0.0.1:8001/')
        else:
            return Response({'message': 'Email verification failed'}, status=status.HTTP_400_BAD_REQUEST)
    

#custom login 
        
class CustomLoginView(RestAuthLoginView):
   
    def post(self, request, *args, **kwargs):
        print("test 1: ", request.data)
        serializer = CustomLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            # Access validated data using serializer.validated_data
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            # Your authentication logic here
            user = authenticate(request, username=username, password=password)
            
            if user is not None:
                # Generate or retrieve the authentication token
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
                    access_token_data = {
                        "qr": qr_code_data,
                        "username": user.username,
                        'user_id': user.id,
                    }
                    access_token = AccessToken.for_user(user)
                    access_token.payload.update(access_token_data)

                    # Return the JWT access token
                    return Response({'access_token': str(access_token),'refresh_token': str(refresh_token)} ,status=status.HTTP_200_OK)
                    # return render(request, 'qrcode.html', {'qr_code_data': qr_code_data, 'username': user.username, 'user_id': user.id})
                else:
                    return Response({'message': 'User has no TOTP device'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'message': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            # Handle validation errors
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

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
        user_id = access_token.payload.get('user_id')

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