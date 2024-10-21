# from django.shortcuts import render

# # Create your views here.
# from django.http import JsonResponse
# from django.views import View
# from django.core.mail import send_mail
# from django.contrib.auth.models import User
# from django.contrib.auth.hashers import make_password
# from django.utils.decorators import method_decorator
# from django.views.decorators.csrf import csrf_exempt
# import json

# @method_decorator(csrf_exempt, name='dispatch')
# class RegistrationView(View):
#     def post(self, request, *args, **kwargs):
#         try:
#             data = json.loads(request.body.decode('utf-8'))
            
#             username = data.get('username')
#             email = data.get('email')
#             password = data.get('password')

#             # Create user
#             user = User.objects.create(
#                 username=username,
#                 email=email,
#                 password=make_password(password)
#             )

#             # Send welcome email
#             send_mail(
#                 'Welcome to My Website',
#                 f'Thank you for registering, {username}! Your user ID is {user.id} and your password is {password}.',
#                 'from@example.com',
#                 [email],
#                 fail_silently=False,
#             )

#             response_data = {
#                 'status': 'success',
#                 'message': 'User registered successfully. Welcome email sent.',
#                 'user_id': user.id
#             }
#             return JsonResponse(response_data, status=201)

#         except Exception as e:
#             response_data = {'status': 'error', 'message': str(e)}
#             return JsonResponse(response_data, status=500)


# # myapp/views.py

# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework import status
# from .models import User
# from .serializers import UserSerializer

# class UserRegistrationView(APIView):
#     def post(self, request, *args, **kwargs):
#         serializer = UserSerializer(data=request.data)
#         if serializer.is_valid():
#             user = serializer.save()

#             # Add your email sending logic here
#             # You can use Django's send_mail function or any third-party library

#             return Response(
#                 {
#                     'message': 'Welcome....User registered successfully',
#                     'user_id': user.id,
#                     'username': user.username,
#                     'email': user.email,
#                     'password': user.password,
#                 },
#                 status=status.HTTP_201_CREATED
#             )

#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# myapp/views.py

from django.core.mail import send_mail
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import User
from .serializers import UserSerializer

class UserRegistrationView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            # Send welcome and success emails
            self.send_welcome_email(user)
            self.send_success_email(user)

            return Response(
                {
                    'message': 'User registered successfully',
                    'user_id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'password': user.password,
                },
                status=status.HTTP_201_CREATED
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def send_welcome_email(self, user):
        subject = 'Welcome to Your Website'
        message = f'Hiii, {user.username},Your user name is {user.username} and password is {user.password}. Thank you, for registering on Your Website!'
        from_email = settings.DEFAULT_FROM_EMAIL
        #to_email = ['ganeshjanjire9696@gmail.com']
        to_email = [user.email]


        send_mail(subject, message, from_email, to_email)

    def send_success_email(self, user):
        subject = 'Registration Success'
        message = f'Hi {user.username}... Your user name is {user.username} and password is {user.password}. Your registration on Your Website was successful!'
        from_email = settings.DEFAULT_FROM_EMAIL
        #to_email = ['ganeshjanjire9696@gmail.com']
        to_email = [user.email]


        send_mail(subject, message, from_email, to_email)


# myapp/views.py

# from django.core.mail import send_mail
# from django.conf import settings
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework import status
# from .models import User
# from .serializers import UserSerializer, PasswordResetSerializer

# class PasswordResetView(APIView):
#     def post(self, request, *args, **kwargs):
#         serializer = PasswordResetSerializer(data=request.data)
#         if serializer.is_valid():
#             email = serializer.validated_data['email']
#             old_password = serializer.validated_data['old_password']
#             new_password = serializer.validated_data['new_password']
#             confirm_password = serializer.validated_data['confirm_password']

#             user = User.objects.get(email=email)

#             # Check if the old password matches the user's current password
#             if not user.check_password(old_password):
#                 return Response({'message': 'Incorrect old password'}, status=status.HTTP_400_BAD_REQUEST)

#             # Check if the new password and confirm password match
#             if new_password != confirm_password:
#                 return Response({'message': 'New password and confirm password do not match'}, status=status.HTTP_400_BAD_REQUEST)

#             # Update the user's password
#             user.set_password(new_password)
#             user.save()

#             # Send password reset success email
#             self.send_password_reset_success_email(user)

#             return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)

#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#     def send_password_reset_success_email(self, user):
#         subject = 'Password Reset Successful'
#         message = f'Hi {user.username}, your password has been successfully reset!'
#         from_email = settings.DEFAULT_FROM_EMAIL
#         to_email = [user.email]

#         send_mail(subject, message, from_email, to_email)

# myapp/views.py

# from django.core.mail import send_mail
# from django.conf import settings
# from django.core.exceptions import MultipleObjectsReturned, ObjectDoesNotExist
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework import status
# from .models import User
# from .serializers import UserSerializer, PasswordResetSerializer

# class PasswordResetView(APIView):
#     def post(self, request, *args, **kwargs):
#         serializer = PasswordResetSerializer(data=request.data)
#         if serializer.is_valid():
#             email = serializer.validated_data['email']
#             old_password = serializer.validated_data['old_password']
#             new_password = serializer.validated_data['new_password']
#             confirm_password = serializer.validated_data['confirm_password']

#             try:
#                 user = User.objects.get(email=email)

#                 # Check if the old password matches the user's current password
#                 if not user.check_password(old_password):
#                     return Response({'message': 'Incorrect old password'}, status=status.HTTP_400_BAD_REQUEST)

#                 # Check if the new password and confirm password match
#                 if new_password != confirm_password:
#                     return Response({'message': 'New password and confirm password do not match'}, status=status.HTTP_400_BAD_REQUEST)

#                 # Update the user's password
#                 user.set_password(new_password)
#                 user.save()

#                 # Send password reset success email
#                 self.send_password_reset_success_email(user)

#                 return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)

#             except MultipleObjectsReturned:
#                 return Response({'message': 'Multiple users found with the same email address'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#             except ObjectDoesNotExist:
#                 return Response({'message': 'User not found with the given email address'}, status=status.HTTP_404_NOT_FOUND)

#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#     def send_password_reset_success_email(self, user):
#         subject = 'Password Reset Successful'
#         message = f'Hi {user.username}, your password has been successfully reset!'
#         from_email = settings.DEFAULT_FROM_EMAIL
#         to_email = [user.email]

#         send_mail(subject, message, from_email, to_email)

# # myapp/views.py

# from django.core.mail import send_mail
# from django.conf import settings
# from django.contrib.auth import get_user_model
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework import status
# from .serializers import PasswordResetSerializer

# User = get_user_model()

# class PasswordResetView(APIView):
#     def post(self, request, *args, **kwargs):
#         serializer = PasswordResetSerializer(data=request.data)
#         if serializer.is_valid():
#             email = serializer.validated_data['email']
#             old_password = serializer.validated_data['old_password']
#             new_password = serializer.validated_data['new_password']
#             confirm_password = serializer.validated_data['confirm_password']

#             try:
#                 user = User.objects.get(email__iexact=email)
#             except User.DoesNotExist:
#                 return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
#             except User.MultipleObjectsReturned:
#                 return Response({'message': 'Multiple users found with the same email'}, status=status.HTTP_400_BAD_REQUEST)

#             # Check if the old password matches the user's current password
#             if not user.check_password(old_password):
#                 return Response({'message': 'Incorrect old password'}, status=status.HTTP_400_BAD_REQUEST)

#             # Check if the new password and confirm password match
#             if new_password != confirm_password:
#                 return Response({'message': 'New password and confirm password do not match'}, status=status.HTTP_400_BAD_REQUEST)

#             # Update the user's password
#             user.set_password(new_password)
#             user.save()

#             # Send password reset success email
#             self.send_password_reset_success_email(user)

#             return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)

#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#     def send_password_reset_success_email(self, user):
#         subject = 'Password Reset Successful'
#         message = f'Hi {user.username}, your password has been successfully reset!'
#         from_email = settings.DEFAULT_FROM_EMAIL
#         to_email = [user.email]

#         send_mail(subject, message, from_email, to_email)

# myapp/views.py

# from django.contrib.auth import get_user_model
# from django.core.mail import send_mail
# from django.conf import settings
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework import status
# from .serializers import PasswordResetSerializer
# from django.contrib.auth import get_user_model

# User = get_user_model()

# class PasswordResetView(APIView):
#     def post(self, request, *args, **kwargs):
#         serializer = PasswordResetSerializer(data=request.data)
#         if serializer.is_valid():
#             email = serializer.validated_data['email']
#             old_password = serializer.validated_data['old_password']
#             new_password = serializer.validated_data['new_password']
#             confirm_password = serializer.validated_data['confirm_password']

#             # Check if the user exists
#             user = User.objects.filter(email=email).first()

#             if not user:
#                 return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)


#             # Check if the old password matches the user's current password
#             if not user.check_password(old_password):
#                 return Response({'message': 'Incorrect old password'}, status=status.HTTP_400_BAD_REQUEST)

#             # Check if the new password and confirm password match
#             if new_password != confirm_password:
#                 return Response({'message': 'New password and confirm password do not match'}, status=status.HTTP_400_BAD_REQUEST)

#             # Update the user's password
#             user.set_password(new_password)
#             user.save()

#             # Send password reset success email
#             self.send_password_reset_success_email(user)

#             return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)

#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#     def send_password_reset_success_email(self, user):
#         subject = 'Password Reset Successful'
#         message = f'Hi {user.username}, your password has been successfully reset!'
#         from_email = settings.DEFAULT_FROM_EMAIL
#         to_email = [user.email]

#         send_mail(subject, message, from_email, to_email)

# myapp/views.py it's work  correct**************************************

# from django.core.mail import send_mail
# from django.conf import settings
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework import status
# from .models import User
# from .serializers import ForgotPasswordSerializer

# class ForgotPasswordView(APIView):
#     def post(self, request, *args, **kwargs):
#         serializer = ForgotPasswordSerializer(data=request.data)
#         if serializer.is_valid():
#             email = serializer.validated_data['email']
#             old_password = serializer.validated_data['old_password']
#             new_password = serializer.validated_data['new_password']
#             confirm_password = serializer.validated_data['confirm_password']

#             # Check if the user exists
#             try:
#                 user = User.objects.get(email=email)
#             except User.DoesNotExist:
#                 return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

#             # Check if the old password matches the user's current password
#             if not user.password == old_password:
#                 return Response({'message': 'Incorrect old password'}, status=status.HTTP_400_BAD_REQUEST)

#             # Check if the new password and confirm password match
#             if new_password != confirm_password:
#                 return Response({'message': 'New password and confirm password do not match'}, status=status.HTTP_400_BAD_REQUEST)

#             # Update the user's password
#             user.password = new_password
#             user.save()

#             # Send password reset success email
#             self.send_password_reset_success_email(user)

#             return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)

#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#     def send_password_reset_success_email(self, user):
#         subject = 'Password Reset Successful'
#         message = f'Hi {user.username}, your password has been successfully reset!'
#         from_email = settings.DEFAULT_FROM_EMAIL
#         to_email = [user.email]

#         send_mail(subject, message, from_email, to_email)


# myapp/views.py

from django.core.mail import send_mail
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import User
from .serializers import UserSerializer, PasswordResetSerializer
# myapp/views.py

from django.urls import reverse
from django.contrib.sites.shortcuts import get_current_site

class PasswordResetRequestView(APIView):
    def post(self, request, *args, **kwargs):
        email = request.data.get('email', None)

        if not email:
            return Response({'error': 'Email is required for password reset.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User with this email does not exist.'}, status=status.HTTP_404_NOT_FOUND)

        reset_token = user.generate_reset_token()

        # Dynamically generate the reset link
        current_site = get_current_site(request)
        domain = current_site.domain
        reset_url = reverse('password-reset-confirm')
        reset_link = f'http://{domain}{reset_url}?token={reset_token}'

        subject = 'Password Reset Link'
        message = f'Click the following link to reset your password: {reset_link}'
        from_email = settings.DEFAULT_FROM_EMAIL
        to_email = [user.email]

        send_mail(subject, message, from_email, to_email)

        return Response({'message': 'Password reset link sent successfully.'}, status=status.HTTP_200_OK)

class PasswordResetView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = PasswordResetSerializer(data=request.data)

        if serializer.is_valid():
            reset_token = serializer.validated_data['reset_token']
            try:
                user = User.objects.get(reset_token=reset_token)
            except User.DoesNotExist:
                return Response({'error': 'Invalid or expired reset token.'}, status=status.HTTP_400_BAD_REQUEST)

            # Update the user's password
            user.password = serializer.validated_data['new_password']
            user.reset_token = None
            user.save()

            return Response({'message': 'Password reset successful.'}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



# myapp/views.py

import pyotp

class OTPSendView(APIView):
    def post(self, request, *args, **kwargs):
        email = request.data.get('email', None)

        if not email:
            return Response({'error': 'Email is required for OTP verification.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User with this email does not exist.'}, status=status.HTTP_404_NOT_FOUND)

        # Generate and send OTP
        otp_secret = pyotp.random_base32()
        totp = pyotp.TOTP(otp_secret)
        otp = totp.now()

        subject = 'OTP for Verification'
        message = f'Your OTP for verification is: {otp}'
        from_email = settings.DEFAULT_FROM_EMAIL
        to_email = [user.email]

        send_mail(subject, message, from_email, to_email)

        # Save the OTP secret to the user model
        user.otp_secret = otp_secret
        user.save()

        return Response({'message': 'OTP sent successfully.'}, status=status.HTTP_200_OK)

# class OTPVerifyView(APIView):
#     def post(self, request, *args, **kwargs):
#         email = request.data.get('email', None)
#         user_input_otp = request.data.get('otp', None)

#         if not email or not user_input_otp:
#             return Response({'error': 'Email and OTP are required for verification.'}, status=status.HTTP_400_BAD_REQUEST)

#         try:
#             user = User.objects.get(email=email)
#         except User.DoesNotExist:
#             return Response({'error': 'User with this email does not exist.'}, status=status.HTTP_404_NOT_FOUND)

#         # Verify OTP
#         totp = pyotp.TOTP(user.otp_secret)
#         is_valid_otp = totp.verify(user_input_otp)

#         if is_valid_otp:
#             return Response({'message': 'OTP verification successful.'}, status=status.HTTP_200_OK)
#         else:
#             return Response({'error': 'Invalid OTP.'}, status=status.HTTP_400_BAD_REQUEST)

# myapp/views.py

import pyotp

class OTPVerifyView(APIView):
    def post(self, request, *args, **kwargs):
        email = request.data.get('email', None)
        user_input_otp = request.data.get('otp', None)

        if not email or not user_input_otp:
            return Response({'error': 'Email and OTP are required for verification.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User with this email does not exist.'}, status=status.HTTP_404_NOT_FOUND)

        # Verify OTP only if otp_secret is not None
        if user.otp_secret:
            totp = pyotp.TOTP(user.otp_secret)
            is_valid_otp = totp.verify(user_input_otp)

            if is_valid_otp:
                return Response({'message': 'OTP verification successful.'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid OTP.'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': 'OTP verification failed. OTP secret not set.'}, status=status.HTTP_400_BAD_REQUEST)

# myapp/views.py

# from django.urls import reverse
# from django.contrib.auth.tokens import default_token_generator
# from django.utils.http import urlsafe_base64_encode
# from django.utils.encoding import force_bytes
# from django.contrib.auth.tokens import PasswordResetTokenGenerator
# from django.core.mail import send_mail
# from django.conf import settings
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework import status
# from .models import User
# from .serializers import ForgotPasswordSerializer

# class ForgotPasswordView(APIView):
#     def post(self, request, *args, **kwargs):
#         serializer = ForgotPasswordSerializer(data=request.data)
#         if serializer.is_valid():
#             email = serializer.validated_data['email']

#             # Check if the user exists
#             try:
#                 user = User.objects.get(email=email)
#             except User.DoesNotExist:
#                 return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

#             # Generate and set reset token
#             user.generate_reset_token()

#             # Build reset link
#             reset_link = self.build_reset_link(request, user)

#             # Send email with reset link
#             self.send_reset_password_email(user, reset_link)

#             return Response({'message': 'Reset password link sent successfully'}, status=status.HTTP_200_OK)

#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#     def build_reset_link(self, request, user):
#         protocol = 'https' if request.is_secure() else 'http'
#         domain = request.get_host()
#         uid = urlsafe_base64_encode(force_bytes(user.id))
#         token = PasswordResetTokenGenerator().make_token(user)
#         return f'{protocol}://{domain}{reverse("reset-password", args=[uid, token])}'

#     def send_reset_password_email(self, user, reset_link):
#         subject = 'Password Reset Link'
#         message = f'Hi {user.username},\n\nYou have requested to reset your password. Click the link below to reset your password:\n\n{reset_link}'
#         from_email = settings.DEFAULT_FROM_EMAIL
#         to_email = [user.email]

#         send_mail(subject, message, from_email, to_email)

