# Generated by Django 4.2.8 on 2024-01-05 15:09

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("orgs", "0133_squashed"),
    ]

    operations = [
        migrations.CreateModel(
            name="Schedule",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "repeat_period",
                    models.CharField(
                        choices=[
                            ("O", "Never"),
                            ("D", "Daily"),
                            ("W", "Weekly"),
                            ("M", "Monthly"),
                        ],
                        max_length=1,
                    ),
                ),
                ("repeat_hour_of_day", models.IntegerField(null=True)),
                ("repeat_minute_of_hour", models.IntegerField(null=True)),
                ("repeat_day_of_month", models.IntegerField(null=True)),
                ("repeat_days_of_week", models.CharField(max_length=7, null=True)),
                ("is_paused", models.BooleanField(default=False)),
                ("last_fire", models.DateTimeField(null=True)),
                ("next_fire", models.DateTimeField()),
                (
                    "org",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="schedules",
                        to="orgs.org",
                    ),
                ),
            ],
            options={
                "indexes": [
                    models.Index(
                        condition=models.Q(("is_paused", False)),
                        fields=["next_fire"],
                        name="schedules_due",
                    )
                ],
            },
        ),
    ]
