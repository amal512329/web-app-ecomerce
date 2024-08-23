
from django.urls import path,include
from .views import (CustomUserRegistrationView,CustomLoginView,CustomTokenObtainPairView,
                    SkipAndLogin,SocialLoginVerificationView,VendorDetailsAPIView,ResetPasswordAPIView
                    )
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,)

urlpatterns = [

    path("user/register/",CustomUserRegistrationView.as_view()),
    path("user/login/",CustomLoginView.as_view(),name='custom-login'),
    path("user/reset_password/",ResetPasswordAPIView.as_view(),name="reset_password"),
    path('user/forgot_password/', include('django_rest_passwordreset.urls', namespace='forgot_password')),
    path("user/social/",SocialLoginVerificationView.as_view(),name="social-verification"),
    path("user/otp-login/",CustomTokenObtainPairView.as_view(),name='custom-login'),
    path('skip-login/',SkipAndLogin.as_view(), name='skip-login'),
    path('vendor_details/<uuid:uuid>/',VendorDetailsAPIView.as_view(), name='vendor-details'),
    path("user/token",TokenObtainPairView.as_view())

]