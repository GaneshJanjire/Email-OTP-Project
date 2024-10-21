# Generated by Django 5.0.2 on 2024-03-05 06:29

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Email_app', '0004_customuser'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='email',
            field=models.EmailField(max_length=254, unique=True),
        ),
        migrations.DeleteModel(
            name='CustomUser',
        ),
    ]