# Generated by Django 4.0.9 on 2023-02-22 18:31

from django.db import migrations

SQL = """
----------------------------------------------------------------------
-- Trigger procedure to update user and system labels on column changes
----------------------------------------------------------------------
CREATE OR REPLACE FUNCTION temba_msg_on_change() RETURNS TRIGGER AS $$
DECLARE
  _new_label_type CHAR(1);
  _old_label_type CHAR(1);
BEGIN
  IF TG_OP IN ('INSERT', 'UPDATE') THEN
    -- prevent illegal message states
    IF NEW.direction = 'I' AND NEW.status NOT IN ('P', 'H') THEN
      RAISE EXCEPTION 'Incoming messages can only be PENDING or HANDLED';
    END IF;
    IF NEW.direction = 'O' AND NEW.visibility = 'A' THEN
      RAISE EXCEPTION 'Outgoing messages cannot be archived';
    END IF;
  END IF;

  -- new message inserted
  IF TG_OP = 'INSERT' THEN
    _new_label_type := temba_msg_determine_system_label(NEW);
    IF _new_label_type IS NOT NULL THEN
      PERFORM temba_insert_system_label(NEW.org_id, _new_label_type, 1);
    END IF;

  -- existing message updated
  ELSIF TG_OP = 'UPDATE' THEN
    _old_label_type := temba_msg_determine_system_label(OLD);
    _new_label_type := temba_msg_determine_system_label(NEW);

    IF _old_label_type IS DISTINCT FROM _new_label_type THEN
      IF _old_label_type IS NOT NULL THEN
        PERFORM temba_insert_system_label(OLD.org_id, _old_label_type, -1);
      END IF;
      IF _new_label_type IS NOT NULL THEN
        PERFORM temba_insert_system_label(NEW.org_id, _new_label_type, 1);
      END IF;
    END IF;

    -- is being archived or deleted (i.e. no longer included for user labels)
    IF OLD.visibility = 'V' AND NEW.visibility != 'V' THEN
      PERFORM temba_insert_message_label_counts(NEW.id, FALSE, -1);
    END IF;

    -- is being restored (i.e. now included for user labels)
    IF OLD.visibility != 'V' AND NEW.visibility = 'V' THEN
      PERFORM temba_insert_message_label_counts(NEW.id, FALSE, 1);
    END IF;

  -- existing message deleted
  ELSIF TG_OP = 'DELETE' THEN
    _old_label_type := temba_msg_determine_system_label(OLD);

    IF _old_label_type IS NOT NULL THEN
      PERFORM temba_insert_system_label(OLD.org_id, _old_label_type, -1);
    END IF;
  END IF;

  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

----------------------------------------------------------------------
-- Handles INSERT statements on msg table
----------------------------------------------------------------------
CREATE OR REPLACE FUNCTION temba_msg_on_insert() RETURNS TRIGGER AS $$
BEGIN
    -- add broadcast counts for all new broadcast values
    INSERT INTO msgs_broadcastmsgcount(broadcast_id, count, is_squashed)
    SELECT broadcast_id, count(*), FALSE FROM newtab WHERE broadcast_id IS NOT NULL GROUP BY broadcast_id;

    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER temba_msg_on_insert
AFTER INSERT ON msgs_msg REFERENCING NEW TABLE AS newtab
FOR EACH STATEMENT EXECUTE PROCEDURE temba_msg_on_insert();

DROP FUNCTION temba_insert_broadcastmsgcount(INTEGER, INT);
"""


class Migration(migrations.Migration):

    dependencies = [("msgs", "0221_remove_msg_msgs_outgoing_to_retry_and_more")]

    operations = [migrations.RunSQL(SQL)]