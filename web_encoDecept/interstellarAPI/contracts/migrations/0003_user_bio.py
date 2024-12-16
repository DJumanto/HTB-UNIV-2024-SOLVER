# Generated by Django 5.1.3 on 2024-11-09 13:28

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('contracts', '0002_contracttemplate_contract'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='bio',
            field=models.TextField(blank=True, help_text='User biography in Markdown format.', null=True),
        ),
    ]