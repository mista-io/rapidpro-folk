# Generated by Django 4.2.3 on 2023-10-23 15:57

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("triggers", "0033_merge_keywords"),
    ]

    operations = [
        migrations.AddField(
            model_name="trigger",
            name="priority",
            field=models.IntegerField(null=True),
        ),
    ]