# Generated by Django 4.0.8 on 2023-01-11 15:35

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("locations", "0027_squashed"),
        ("tickets", "0044_squashed"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("orgs", "0118_squashed"),
    ]

    operations = [
        migrations.AddField(
            model_name="usersettings",
            name="team",
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.PROTECT, to="tickets.team"),
        ),
        migrations.AddField(
            model_name="usersettings",
            name="user",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.PROTECT, related_name="usersettings", to="orgs.user"
            ),
        ),
        migrations.AddField(
            model_name="orgmembership",
            name="org",
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="orgs.org"),
        ),
        migrations.AddField(
            model_name="orgmembership",
            name="user",
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="orgs.user"),
        ),
        migrations.AddField(
            model_name="org",
            name="country",
            field=models.ForeignKey(
                blank=True,
                help_text="The country this organization should map results for.",
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                to="locations.adminboundary",
            ),
        ),
        migrations.AddField(
            model_name="org",
            name="created_by",
            field=models.ForeignKey(
                help_text="The user which originally created this item",
                on_delete=django.db.models.deletion.PROTECT,
                related_name="%(app_label)s_%(class)s_creations",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="org",
            name="modified_by",
            field=models.ForeignKey(
                help_text="The user which last modified this item",
                on_delete=django.db.models.deletion.PROTECT,
                related_name="%(app_label)s_%(class)s_modifications",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="org",
            name="parent",
            field=models.ForeignKey(
                null=True, on_delete=django.db.models.deletion.PROTECT, related_name="children", to="orgs.org"
            ),
        ),
        migrations.AddField(
            model_name="org",
            name="users",
            field=models.ManyToManyField(related_name="orgs", through="orgs.OrgMembership", to="orgs.user"),
        ),
        migrations.AddField(
            model_name="invitation",
            name="created_by",
            field=models.ForeignKey(
                help_text="The user which originally created this item",
                on_delete=django.db.models.deletion.PROTECT,
                related_name="%(app_label)s_%(class)s_creations",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="invitation",
            name="modified_by",
            field=models.ForeignKey(
                help_text="The user which last modified this item",
                on_delete=django.db.models.deletion.PROTECT,
                related_name="%(app_label)s_%(class)s_modifications",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="invitation",
            name="org",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.PROTECT, related_name="invitations", to="orgs.org"
            ),
        ),
        migrations.AddField(
            model_name="backuptoken",
            name="user",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.PROTECT, related_name="backup_tokens", to="orgs.user"
            ),
        ),
        migrations.AlterUniqueTogether(
            name="orgmembership",
            unique_together={("org", "user")},
        ),
    ]