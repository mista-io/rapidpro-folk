# Generated by Django 4.2.3 on 2023-11-07 16:56

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("triggers", "0038_trigger_triggers_scheduled_trigger_has_schedule"),
    ]

    operations = [
        migrations.RemoveConstraint(
            model_name="trigger",
            name="triggers_scheduled_trigger_has_schedule",
        ),
        migrations.AddConstraint(
            model_name="trigger",
            constraint=models.CheckConstraint(
                check=models.Q(
                    models.Q(("trigger_type", "S"), _negated=True),
                    ("schedule__isnull", False),
                    ("is_active", False),
                    _connector="OR",
                ),
                name="triggers_scheduled_trigger_has_schedule",
            ),
        ),
    ]