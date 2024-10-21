
# from django.urls import path
# from .views import *

# urlpatterns = [
#     path('register/', UserRegistrationView.as_view(), name='user-registration'),
#     path('forgot_password/', ForgotPasswordView.as_view(), name='forgot-password'),
# ]

# myapp/urls.py

from django.urls import path
from .views import UserLoginView, UserRegistrationView, PasswordResetRequestView, PasswordResetView

# urlpatterns = [
#     path('register/', UserRegistrationView.as_view(), name='user-registration'),
#     path('reset-password/request/', PasswordResetRequestView.as_view(), name='password-reset-request'),
#     path('reset-password/confirm/', PasswordResetView.as_view(), name='password-reset-confirm'),
# ]

# myapp/urls.py

from django.urls import path
from .views import UserRegistrationView, PasswordResetRequestView, PasswordResetView, OTPSendView, OTPVerifyView

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='user-registration'),
    path('otp/send/', OTPSendView.as_view(), name='otp-send'),
    path('otp/verify/', OTPVerifyView.as_view(), name='otp-verify'),

    path('reset-password/request/', PasswordResetRequestView.as_view(), name='password-reset-request'),
    path('reset-password/confirm/', PasswordResetView.as_view(), name='password-reset-confirm'),
    
#    path('login/', UserLoginView.as_view(), name='user-login'),

]
