package io.github.baylorpaul.webauthn4jmicronaut.repo;

import io.github.baylorpaul.webauthn4jmicronaut.entity.PasskeyUserHandle;
import io.micronaut.data.annotation.Query;
import io.micronaut.data.jdbc.annotation.JdbcRepository;
import io.micronaut.data.model.query.builder.sql.Dialect;
import io.micronaut.data.repository.PageableRepository;

import java.util.Optional;

@JdbcRepository(dialect = Dialect.POSTGRES)
public interface PasskeyUserHandleRepository extends PageableRepository<PasskeyUserHandle, String> {

	/**
	 * Delete all passkey_user_handle records, except those with a user ID or a passkey_challenge that has not expired.
	 * This will also delete the corresponding passkey_challenge records via ON DELETE CASCADE.
	 */
// TODO remove this method - we don't need it anymore
	@Query("DELETE FROM public.passkey_user_handle WHERE user_id IS NULL AND id NOT IN (SELECT passkey_user_handle_id FROM public.passkey_challenge WHERE challenge_expiration >= current_timestamp)")
	void deleteWhereUserIdIsNullAndHasNoUnexpiredChallenge();

	/** Delete passkey_user_handle records that have neither a user nor a passkey challenge */
	@Query("DELETE FROM public.passkey_user_handle WHERE user_id IS NULL AND id NOT IN (SELECT passkey_user_handle_id FROM public.passkey_challenge)")
	void deleteWhereUserIdIsNullAndHasNoChallenge();

	Optional<PasskeyUserHandle> findByUserId(long userId);
}
