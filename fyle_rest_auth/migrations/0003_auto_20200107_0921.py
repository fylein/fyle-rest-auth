# Generated by Django 3.0.2 on 2020-01-07 09:21

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('fyle_rest_auth', '0002_auto_20200101_1205'),
    ]

    operations = [
        migrations.AlterField(
            model_name='authtokens',
            name='user',
            field=models.OneToOneField(help_text='User table relation', on_delete=django.db.models.deletion.PROTECT, to=settings.AUTH_USER_MODEL),
        ),
    ]
