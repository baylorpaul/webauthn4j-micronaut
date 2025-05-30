--------------------------------------------------------------------------------
-- Title:  Initial database script
-- Date:   2025-05-29
-- Author: Paul Poley
--
-- Comments: Initial table creation, etc.
--------------------------------------------------------------------------------

--------------------------------------------------------------------------------
-- DB Users, Permissions...
--------------------------------------------------------------------------------

--N/A

--------------------------------------------------------------------------------
-- Tables, Tablespaces, Sequences, Comments
--------------------------------------------------------------------------------

CREATE TABLE public.user
(
	id                                   BIGSERIAL,
	email                                varchar(256) NOT NULL,
	name                                 varchar(256) NOT NULL,
    enabled                              boolean NOT NULL,
    created                              timestamptz NOT NULL,
    updated                              timestamptz NOT NULL,
	CONSTRAINT pk_user                   PRIMARY KEY(id)
)
	TABLESPACE pg_default
;
COMMENT ON TABLE public.user IS 'A user of the platform';
COMMENT ON COLUMN public.user.email IS 'The email address for the user';
COMMENT ON COLUMN public.user.name IS 'The name of the user';
COMMENT ON COLUMN public.user.enabled IS 'true if the user is currently enabled';

--------------------------------------------------------------------------------
-- Sequence Alteration
--------------------------------------------------------------------------------

--N/A

--------------------------------------------------------------------------------
-- Functions, Procedures
--------------------------------------------------------------------------------

-- Function for triggers on tables with "created" and "updated" timestamptz fields
CREATE FUNCTION fn_for_created_and_updated_biu() RETURNS TRIGGER AS $$
BEGIN
	IF TG_OP = 'INSERT' THEN
		-- Remove microseconds since Java, etc. only stores values to millisecond precision
		NEW.created := date_trunc('milliseconds', now());
		NEW.updated := NEW.created;
	ELSIF TG_OP = 'UPDATE' THEN
		IF NEW.created != OLD.created THEN
			RAISE EXCEPTION 'Cannot change the created date on table "%". OLD: %, NEW: %', TG_TABLE_NAME, OLD.created, NEW.created;
		END IF;
		NEW.updated := date_trunc('milliseconds', now());
	END IF;
	RETURN NEW;
END;
$$ LANGUAGE plpgsql;

--------------------------------------------------------------------------------
-- Triggers
--------------------------------------------------------------------------------

CREATE TRIGGER user__timestamp_biu BEFORE INSERT OR UPDATE ON public.user FOR EACH ROW EXECUTE PROCEDURE fn_for_created_and_updated_biu();

--------------------------------------------------------------------------------
-- Indexes
--------------------------------------------------------------------------------

CREATE INDEX user__email__idx ON public.user (email);

--------------------------------------------------------------------------------
-- Foreign Keys, Constraints...
--------------------------------------------------------------------------------

--Ensure user.email is case-insensitive unique. We can't do a regular unique "constraint" while using LOWER().
CREATE UNIQUE INDEX uq_user__lower_email__idx ON public.user (LOWER(email));

--------------------------------------------------------------------------------
-- Data
--------------------------------------------------------------------------------

--N/A

--------------------------------------------------------------------------------
-- Rollback
--------------------------------------------------------------------------------

--N/A
