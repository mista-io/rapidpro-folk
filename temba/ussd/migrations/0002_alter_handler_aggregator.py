# Generated by Django 4.2.8 on 2024-01-27 11:11

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("ussd", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="handler",
            name="aggregator",
            field=models.CharField(
                choices=[("MISTA", "MISTA"), ("AFRICAS_TALKING", "Africa's Talking")],
                default="MISTA",
                help_text="Your USSD aggregator",
                max_length=20,
                verbose_name="Aggregator",
            ),
        ),
    ]
