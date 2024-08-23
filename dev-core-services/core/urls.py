
from django.contrib import admin
from django.urls import path,include,re_path
from accounts.views import CustomEmailConfirmView,FinishAndRedirectView


urlpatterns = [
    path('admin/', admin.site.urls),
    path('dj-rest-auth/', include('dj_rest_auth.urls')),
    path('', include('dj_rest_auth.urls')),
    path("dj-rest-auth/registration/", include("dj_rest_auth.registration.urls")),
    path("dj-rest-auth/", include("dj_rest_auth.urls")),
    path('api/v1/',include('accounts.urls')),
    re_path(
        r'^account-confirm-email/(?P<key>[-:\w]+)/$',
        CustomEmailConfirmView.as_view(),
        name='account_confirm_email',
    ),
    path('finish_and_redirect/', FinishAndRedirectView.as_view(), name='finish_and_redirect'),

    # accounts: api/v1/accounts/
]
