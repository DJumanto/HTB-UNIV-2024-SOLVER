# Generated by Django 5.1.3 on 2024-11-11 00:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('contracts', '0004_remove_contracttemplate_contract_template_name_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='contracttemplate',
            name='data',
            field=models.TextField(help_text='Serialized contract template data', null=True),
        ),
    ]
