# Generated by Django 5.0.9 on 2024-11-11 17:14

import taggit.managers
import utilities.json
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('extras', '0121_customfield_related_object_filter'),
        ('netbox_ddns', '0009_alter_dnsstatus_id_alter_extradnsname_id_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='extradnsname',
            name='created',
            field=models.DateTimeField(auto_now_add=True, null=True),
        ),
        migrations.AddField(
            model_name='extradnsname',
            name='custom_field_data',
            field=models.JSONField(blank=True, default=dict, encoder=utilities.json.CustomFieldJSONEncoder),
        ),
        migrations.AddField(
            model_name='extradnsname',
            name='last_updated',
            field=models.DateTimeField(auto_now=True, null=True),
        ),
        migrations.AddField(
            model_name='extradnsname',
            name='tags',
            field=taggit.managers.TaggableManager(through='extras.TaggedItem', to='extras.Tag'),
        ),
    ]
