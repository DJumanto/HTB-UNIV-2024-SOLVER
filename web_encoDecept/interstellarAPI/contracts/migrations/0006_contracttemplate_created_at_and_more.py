# Generated by Django 5.1.3 on 2024-11-11 13:59

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('contracts', '0005_alter_contracttemplate_data'),
    ]

    operations = [
        migrations.AddField(
            model_name='contracttemplate',
            name='created_at',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='contracttemplate',
            name='description',
            field=models.TextField(blank=True, help_text='Description of the contract template', null=True),
        ),
        migrations.AddField(
            model_name='contracttemplate',
            name='updated_at',
            field=models.DateTimeField(auto_now=True),
        ),
        migrations.AddField(
            model_name='contracttemplate',
            name='user',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='contract_templates', to=settings.AUTH_USER_MODEL),
        ),
    ]
