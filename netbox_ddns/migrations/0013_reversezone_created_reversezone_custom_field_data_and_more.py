# Generated by Django 5.0.9 on 2025-01-08 19:51

import taggit.managers
import utilities.json
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('extras', '0122_charfield_null_choices'),
        ('netbox_ddns', '0012_zone_created_zone_custom_field_data_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='reversezone',
            name='created',
            field=models.DateTimeField(auto_now_add=True, null=True),
        ),
        migrations.AddField(
            model_name='reversezone',
            name='custom_field_data',
            field=models.JSONField(blank=True, default=dict, encoder=utilities.json.CustomFieldJSONEncoder),
        ),
        migrations.AddField(
            model_name='reversezone',
            name='last_updated',
            field=models.DateTimeField(auto_now=True, null=True),
        ),
        migrations.AddField(
            model_name='reversezone',
            name='tags',
            field=taggit.managers.TaggableManager(through='extras.TaggedItem', to='extras.Tag'),
        ),
    ]
