--------------------------------------------------------------------------------
-- Title:  Confirmation Token Reuse Protection
-- Date:   2025-05-30
-- Author: Paul Poley
--
-- Comments: When a confirmation token is issued, it is not persisted. For
--           confirmation tokens that are not reusable, we will persist the used
--           tokens until at least their expiration date so that we can reject
--           requests for previously used confirmation tokens that are not
--           reusable.
--------------------------------------------------------------------------------

--------------------------------------------------------------------------------
-- DB Users, Permissions...
--------------------------------------------------------------------------------

--N/A

--------------------------------------------------------------------------------
-- Tables, Tablespaces, Sequences, Comments
--------------------------------------------------------------------------------

CREATE TABLE public.utilized_confirmation_token
(
	id                                   BIGSERIAL,
    user_id                              bigint NOT NULL,
    type                                 varchar(50) NOT NULL,
	utilized_token                       text NOT NULL,
	expiration_date                      timestamptz NOT NULL,
	created                              timestamptz NOT NULL,
	updated                              timestamptz NOT NULL,
	CONSTRAINT pk_utilized_confirmation_token  PRIMARY KEY(id),
    CONSTRAINT fk_utilized_confirmation_token__user_id  FOREIGN KEY(user_id) REFERENCES public.user ON DELETE CASCADE,
	CONSTRAINT uq_utilized_confirmation_token__utilized_token UNIQUE (utilized_token)
)
	TABLESPACE pg_default
;
COMMENT ON TABLE public.utilized_confirmation_token IS 'Confirmation tokens that have been exercised/utilized, and are no longer valid. Tokens are not persisted here until they are exercised/utilized, and only one-time use tokens are persisted here. While the expiration date is duplicated here, the expiration date and any associated data is stored in the claims of the token itself.';
COMMENT ON COLUMN public.utilized_confirmation_token.user_id IS 'The user for which the confirmation token has been exercised';
COMMENT ON COLUMN public.utilized_confirmation_token.type IS 'The type of confirmation token, such as PASSKEY_ADDITION';
COMMENT ON COLUMN public.utilized_confirmation_token.utilized_token IS 'The confirmation token which has been exercised/utilized, and is no longer valid';
COMMENT ON COLUMN public.utilized_confirmation_token.expiration_date IS 'When the confirmation token expires. Once this date has passed, the record may be deleted since the expiration date in the token claims will invalidate the token by itself.';

--------------------------------------------------------------------------------
-- Sequence Alteration
--------------------------------------------------------------------------------

SELECT setval('public.utilized_confirmation_token_id_seq', 15300);

--------------------------------------------------------------------------------
-- Functions, Procedures
--------------------------------------------------------------------------------

--N/A

--------------------------------------------------------------------------------
-- Triggers
--------------------------------------------------------------------------------

CREATE TRIGGER utilized_confirmation_token__timestamp_biu  BEFORE INSERT OR UPDATE ON public.utilized_confirmation_token  FOR EACH ROW EXECUTE PROCEDURE fn_for_created_and_updated_biu();

--------------------------------------------------------------------------------
-- Indexes
--------------------------------------------------------------------------------

-- No need for a separate index. The unique constraint automatically creates a unique index.
--CREATE INDEX utilized_confirmation_token__utilized_token__idx ON public.utilized_confirmation_token (utilized_token);

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
DROP TABLE public.utilized_confirmation_token;

DELETE FROM public.flyway_schema_history WHERE installed_rank = 2 AND script = '01-A/V01_002__confirmation_tokens.sql';
*/
