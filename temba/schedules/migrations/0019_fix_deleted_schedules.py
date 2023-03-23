# Generated by Django 4.1.7 on 2023-03-06 14:25

from django.db import migrations


def fix_deleted_schedules(apps, schema_editor):
    Schedule = apps.get_model("schedules", "Schedule")

    ghost_schedules = Schedule.objects.filter(is_active=True, broadcast__is_active=False)
    num_schedules = ghost_schedules.count()
    if num_schedules:
        ghost_schedules.update(is_active=False)

        print(f"Deleted {num_schedules} schedules with deleted broadcasts")


def reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("schedules", "0018_squashed"),
    ]

    operations = [migrations.RunPython(fix_deleted_schedules, reverse)]
