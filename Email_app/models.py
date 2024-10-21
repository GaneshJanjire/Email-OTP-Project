from django.db import models

# Create your models here.
# myapp/models.py

# from django.db import models

# class User(models.Model):
#     username = models.CharField(max_length=255)
#     email = models.EmailField(unique=True)
#     password = models.CharField(max_length=255)


# myapp/models.py
# myapp/models.py it's work correct

# import uuid
# from django.db import models

# class User(models.Model):
#     username = models.CharField(max_length=255)
#     email = models.EmailField(unique=True)
#     password = models.CharField(max_length=255)
#     reset_token = models.UUIDField(default=uuid.uuid4, editable=False)


# # myapp/models.py
# its correct
# # from django.db import models
# # from django.utils.crypto import get_random_string

# # class User(models.Model):
# #     username = models.CharField(max_length=255)
# #     email = models.EmailField(unique=True)
# #     password = models.CharField(max_length=255)
# #     reset_token = models.CharField(max_length=255, blank=True, null=True)

# #     def generate_reset_token(self):
# #         self.reset_token = get_random_string(length=32)
# #         self.save()
# #         return self.reset_token

# myapp/models.py

# from django.db import models
# from django.utils.crypto import get_random_string

# class User(models.Model):
#     username = models.CharField(max_length=255)
#     email = models.EmailField(unique=True)
#     password = models.CharField(max_length=255)
#     reset_token = models.CharField(max_length=255, blank=True, null=True)
#     otp = models.CharField(max_length=6, blank=True, null=True)

#     def generate_otp(self):
#         self.otp = get_random_string(length=6, allowed_chars='0123456789')
#         self.save()
#         return self.otp
    
#     def generate_reset_token(self):
#         self.reset_token = get_random_string(length=32)
#         self.save()
#         return self.reset_token

# myapp/models.py

from django.db import models
from django.utils.crypto import get_random_string

class User(models.Model):
    username = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)
    otp_secret = models.CharField(max_length=255, blank=True, null=True)

    def generate_reset_token(self):
        self.reset_token = get_random_string(length=32)
        self.save()
        return self.reset_token

    def generate_otp_secret(self):
        self.otp_secret = get_random_string(length=32)
        self.save()
        return self.otp_secret


# myapp/models.py

# import uuid
# from django.db import models

# class User(models.Model):
#     username = models.CharField(max_length=255)
#     email = models.EmailField(unique=True)
#     password = models.CharField(max_length=255)
#     reset_token = models.UUIDField(default=uuid.uuid4, editable=False)

#     def generate_reset_token(self):
#         self.reset_token = uuid.uuid4()
#         self.save()



# myapp/models.py
# myapp/models.py

# from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
# from django.db import models
# from django.utils import timezone

# class CustomUserManager(BaseUserManager):
#     def create_user(self, email, username, password=None, **extra_fields):
#         if not email:
#             raise ValueError('The Email field must be set')
#         email = self.normalize_email(email)
#         user = self.model(email=email, username=username, **extra_fields)
#         user.set_password(password)
#         user.save(using=self._db)
#         return user

#     def create_superuser(self, email, username, password=None, **extra_fields):
#         extra_fields.setdefault('is_staff', True)
#         extra_fields.setdefault('is_superuser', True)

#         return self.create_user(email, username, password, **extra_fields)

# class CustomUser(AbstractBaseUser, PermissionsMixin):
#     email = models.EmailField(unique=True)
#     username = models.CharField(max_length=30, unique=True)
#     is_active = models.BooleanField(default=True)
#     is_staff = models.BooleanField(default=False)
#     date_joined = models.DateTimeField(default=timezone.now)

#     # Add unique related_names to avoid clashes with auth.User model
#     groups = models.ManyToManyField(
#         'auth.Group',
#         related_name='customuser_set',
#         related_query_name='customuser',
#         blank=True,
#         verbose_name='groups',
#         help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.',
#     )
    
#     user_permissions = models.ManyToManyField(
#         'auth.Permission',
#         related_name='customuser_set',
#         related_query_name='customuser',
#         blank=True,
#         verbose_name='user permissions',
#         help_text='Specific permissions for this user.',
#     )

#     objects = CustomUserManager()

#     USERNAME_FIELD = 'email'
#     REQUIRED_FIELDS = ['username']

#     def __str__(self):
#         return self.email

