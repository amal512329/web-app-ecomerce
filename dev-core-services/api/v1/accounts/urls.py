
from django.urls import path
from .views import CustomUserRegistrationView,CustomLoginView,CustomTokenObtainPairView,SkipAndLogin
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,)

urlpatterns = [

   
    path("user/register/",CustomUserRegistrationView.as_view()),
    path("user/login/",CustomLoginView.as_view(),name='custom-login'),
    path("user/otp-login/",CustomTokenObtainPairView.as_view(),name='custom-login'),
    path('skip-login/',SkipAndLogin.as_view(), name='skip-login'),
    

   

]