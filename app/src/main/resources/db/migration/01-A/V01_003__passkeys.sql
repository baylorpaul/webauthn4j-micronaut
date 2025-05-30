--------------------------------------------------------------------------------
-- Title:  Support Passkey/WebAuthn logins
-- Date:   2025-05-30
-- Author: Paul Poley
--
-- Comments: Add support for Passkey/WebAuthn logins
--------------------------------------------------------------------------------

--------------------------------------------------------------------------------
-- DB Users, Permissions...
--------------------------------------------------------------------------------

--N/A

--------------------------------------------------------------------------------
-- Tables, Tablespaces, Sequences, Comments
--------------------------------------------------------------------------------

CREATE TABLE public.passkey_credentials
(
    id                                   BIGSERIAL,
    user_id                              bigint NOT NULL,
    credential_id                        text NOT NULL,
    attested_credential_data             bytea NOT NULL,
    attestation_statement_envelope       bytea NOT NULL,
    authenticator_extensions             text,
    signature_count                      bigint NOT NULL,
    type                                 text NOT NULL,
    client_extensions                    text,
    transports                           text[],
    uv_initialized                       boolean NOT NULL,
    backup_eligible                      boolean NOT NULL,
    backup_state                         boolean NOT NULL,
    last_used_date                       timestamptz,
    passkey_name                         varchar(20),
    created                              timestamptz NOT NULL,
    updated                              timestamptz NOT NULL,
    CONSTRAINT pk_passkey_credentials  PRIMARY KEY(id),
    CONSTRAINT fk_passkey_credentials__user_id  FOREIGN KEY(user_id) REFERENCES public.user ON DELETE CASCADE,
    CONSTRAINT uq_passkey_credentials__credential_id UNIQUE (credential_id)
)
    TABLESPACE pg_default
;
COMMENT ON TABLE public.passkey_credentials IS 'Passkey/WebAuthn credentials for a user. The attested_credential_data contains the public key.';
COMMENT ON COLUMN public.passkey_credentials.user_id IS 'The user that may authenticate with these Passkey/WebAuthn credentials';
COMMENT ON COLUMN public.passkey_credentials.credential_id IS 'The Base64Url encoded Passkey/WebAuthn credential ID. This also exists in the attested_credential_data.';
COMMENT ON COLUMN public.passkey_credentials.attested_credential_data IS 'The attested credential data (aaguid, credentialId, credentialPublicKey) as a byte array. The "aaguid" identifies the model of the authenticator (not the specific instance of the authenticator). The "credentialPublicKey" is written to the byte array via CBOR (Concise Binary Object Representation) encoding. No encryption is required, as this is a public key, and the server never has access to the private key. See https://www.w3.org/TR/webauthn-1/#sec-attested-credential-data';
COMMENT ON COLUMN public.passkey_credentials.attestation_statement_envelope IS 'The attestation statement envelope, encoded in CBOR (Concise Binary Object Representation). This includes the attestation type (E.g. "direct", "indirect", "none") in the "fmt" key. It also includes the attestation statement in the "attStmt" key.';
COMMENT ON COLUMN public.passkey_credentials.authenticator_extensions IS 'the authenticator extensions supported as JSON';
COMMENT ON COLUMN public.passkey_credentials.signature_count IS 'Counter to prevent replay attacks';
COMMENT ON COLUMN public.passkey_credentials.type IS 'Credential type. E.g. "webauthn.create", "webauthn.get"';
COMMENT ON COLUMN public.passkey_credentials.client_extensions IS 'the client extensions supported as JSON';
COMMENT ON COLUMN public.passkey_credentials.transports IS 'the transport methods supported. E.g. ["internal","hybrid"]';
COMMENT ON COLUMN public.passkey_credentials.uv_initialized IS 'Indicates whether user verification was performed';
COMMENT ON COLUMN public.passkey_credentials.backup_eligible IS 'The value of the Backup Eligibility flag when the public key credential source was created';
COMMENT ON COLUMN public.passkey_credentials.backup_state IS 'Whether the public key credential source is currently backed up';
COMMENT ON COLUMN public.passkey_credentials.last_used_date IS 'Timestamp for last usage of the credential in an authentication process';
COMMENT ON COLUMN public.passkey_credentials.passkey_name IS 'An optional free-form name or comment to further describe the usage of the passkey. E.g. a label to help users distinguish between devices, such as "MacBook Pro" or "Work Phone"';


CREATE TABLE public.passkey_user_handle
(
    id                                   text NOT NULL,
    user_id                              bigint,
    email                                varchar(256),
    name                                 varchar(256),
    created                              timestamptz NOT NULL,
    updated                              timestamptz NOT NULL,
    CONSTRAINT pk_passkey_user_handle  PRIMARY KEY(id),
    CONSTRAINT fk_passkey_user_handle__user_id  FOREIGN KEY(user_id) REFERENCES public.user ON DELETE CASCADE,
    CONSTRAINT uq_passkey_user_handle__user_id UNIQUE (user_id)
)
    TABLESPACE pg_default
;
COMMENT ON TABLE public.passkey_user_handle IS 'A Passkey/WebAuthn handle, which may link passkey credentials to a user. A handle is not linked to a user until registration is verified.';
COMMENT ON COLUMN public.passkey_user_handle.id IS 'A random 64 byte ID, encoded in Base64Url, as the user handle. This ID never changes, does NOT match the user ID, and has no PII (Personally identifiable information).';
COMMENT ON COLUMN public.passkey_user_handle.user_id IS 'The user with which this handle is linked, if any';
COMMENT ON COLUMN public.passkey_user_handle.email IS 'The email address for the user handle. This is only used during registration, before the user is created. It is NOT unique, in case a registration is not successful.';
COMMENT ON COLUMN public.passkey_user_handle.name IS 'The name of the user. This is only used during registration, before the user is created.';


CREATE TABLE public.passkey_challenge
(
    session_id                           uuid NOT NULL,
    passkey_user_handle_id               text,
    challenge_expiration                 timestamptz NOT NULL,
    challenge                            text NOT NULL,
    created                              timestamptz NOT NULL,
    updated                              timestamptz NOT NULL,
    CONSTRAINT pk_passkey_challenge  PRIMARY KEY(session_id),
    CONSTRAINT fk_passkey_challenge__passkey_user_handle  FOREIGN KEY(passkey_user_handle_id) REFERENCES public.passkey_user_handle ON DELETE CASCADE
)
    TABLESPACE pg_default
;
COMMENT ON TABLE public.passkey_challenge IS 'A Passkey/WebAuthn challenge and session ID.';
COMMENT ON COLUMN public.passkey_challenge.session_id IS 'The random session ID for the short-lived challenge';
COMMENT ON COLUMN public.passkey_challenge.passkey_user_handle_id IS 'The passkey user handle, if the challenge is for Passkey/WebAuthn registration. No reference is needed for Passkey/WebAuthn authentication, because the Passkey/WebAuthn credential ID may be used in that case to look up the passkey_credentials record.';
COMMENT ON COLUMN public.passkey_challenge.challenge_expiration IS 'When the challenge expires';
COMMENT ON COLUMN public.passkey_challenge.challenge IS 'The Passkey/WebAuthn challenge for the session, encoded in Base64Url, which is used for a brief period of time during Passkey/WebAuthn registration and authentication';

--------------------------------------------------------------------------------
-- Sequence Alteration
--------------------------------------------------------------------------------

SELECT setval('public.passkey_credentials_id_seq', 3900);

--------------------------------------------------------------------------------
-- Functions, Procedures
--------------------------------------------------------------------------------

--N/A

--------------------------------------------------------------------------------
-- Triggers
--------------------------------------------------------------------------------

CREATE TRIGGER passkey_credentials__timestamp_biu BEFORE INSERT OR UPDATE ON public.passkey_credentials FOR EACH ROW EXECUTE PROCEDURE fn_for_created_and_updated_biu();
CREATE TRIGGER passkey_user_handle__timestamp_biu BEFORE INSERT OR UPDATE ON public.passkey_user_handle FOR EACH ROW EXECUTE PROCEDURE fn_for_created_and_updated_biu();
CREATE TRIGGER passkey_challenge__timestamp_biu   BEFORE INSERT OR UPDATE ON public.passkey_challenge   FOR EACH ROW EXECUTE PROCEDURE fn_for_created_and_updated_biu();

--------------------------------------------------------------------------------
-- Indexes
--------------------------------------------------------------------------------

CREATE INDEX passkey_credentials__user_id__idx ON public.passkey_credentials (user_id);
CREATE INDEX passkey_user_handle__user_id__idx ON public.passkey_user_handle (user_id);

--------------------------------------------------------------------------------
-- Foreign Keys, Constraints...
--------------------------------------------------------------------------------

--N/A

--------------------------------------------------------------------------------
-- Data
--------------------------------------------------------------------------------

--N/A

--------------------------------------------------------------------------------
-- Rollback
--------------------------------------------------------------------------------

/*
DROP TABLE public.passkey_challenge;
DROP TABLE public.passkey_user_handle;
DROP TABLE public.passkey_credentials;

DELETE FROM public.flyway_schema_history WHERE installed_rank = 3 AND script = '01-A/V01_003__passkeys.sql';
*/
