# Generated by Django 3.2.9 on 2022-01-13 17:06

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("flows", "0265_flowsession_wait_resume_on_expire"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="flowrun",
            name="events",
        ),
        migrations.DeleteModel(
            name="FlowPathRecentRun",
        ),
    ]
