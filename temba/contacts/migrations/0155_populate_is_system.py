# Generated by Django 4.0.3 on 2022-03-21 19:58

from django.db import migrations


def populate_group_is_system(apps, schema_editor):
    ContactGroup = apps.get_model("contacts", "ContactGroup")

    num_updated = 0

    while True:
        batch = list(ContactGroup.all_groups.filter(is_system=None).only("id", "group_type")[:1000])
        if not batch:
            break

        system, non_system = [], []
        for g in batch:
            if g.group_type == "U":
                non_system.append(g)
            else:
                system.append(g)

        ContactGroup.all_groups.filter(id__in=[g.id for g in system]).update(is_system=True)
        ContactGroup.all_groups.filter(id__in=[g.id for g in non_system]).update(is_system=False)
        num_updated += len(batch)

    if num_updated:
        print(f"Populated is_system on {num_updated} contact groups")


def reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("contacts", "0154_contactgroup_is_system"),
    ]

    operations = [migrations.RunPython(populate_group_is_system, reverse)]