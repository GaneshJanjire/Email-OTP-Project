# myapp/serializers.py

from rest_framework import serializers
from .models import User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password']

# myapp/serializers.py

# from rest_framework import serializers
# from .models import User

# class PasswordResetSerializer(serializers.Serializer):
#     email = serializers.EmailField()
#     old_password = serializers.CharField()
#     new_password = serializers.CharField()
#     confirm_password = serializers.CharField()


# myapp/serializers.py

# myapp/serializers.py

from rest_framework import serializers

class PasswordResetSerializer(serializers.Serializer):
    old_password = serializers.CharField()
    new_password = serializers.CharField()
    confirm_password = serializers.CharField()
    reset_token = serializers.CharField()
    
# myapp/serializers.py
#adddedddd 
from rest_framework import serializers

class OTPSerializer(serializers.Serializer):
    otp = serializers.CharField()

#it's work correct
# from rest_framework import serializers

# class ForgotPasswordSerializer(serializers.Serializer):
#     email = serializers.EmailField()
#     old_password = serializers.CharField()
#     new_password = serializers.CharField()
#     confirm_password = serializers.CharField()
    
# pip install pyotp


# myapp/serializers.py

# from rest_framework import serializers

# class ForgotPasswordSerializer(serializers.Serializer):
#     email = serializers.EmailField()
#     old_password = serializers.CharField()
#     new_password = serializers.CharField()
#     confirm_password = serializers.CharField()
#     reset_token = serializers.UUIDField(write_only=True, required=False)
