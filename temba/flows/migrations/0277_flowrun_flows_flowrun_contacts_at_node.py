# Generated by Django 4.0.2 on 2022-03-02 15:58

from django.db import migrations, models

SQL = """
DROP INDEX IF EXISTS flows_flowrun_org_current_node_uuid_active_only;
DROP INDEX IF EXISTS flows_flowrun_contact_flow_created_on_id_idx;
"""


class Migration(migrations.Migration):

    dependencies = [
        ("flows", "0276_remove_flowrun_delete_reason_and_more"),
    ]

    operations = [
        migrations.RunSQL(SQL),
        migrations.AddIndex(
            model_name="flowrun",
            index=models.Index(
                condition=models.Q(("status__in", ("A", "W"))),
                fields=["org", "current_node_uuid"],
                include=("contact",),
                name="flows_flowrun_contacts_at_node",
            ),
        ),
    ]
