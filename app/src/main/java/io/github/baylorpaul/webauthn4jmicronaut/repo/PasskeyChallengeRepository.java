package io.github.baylorpaul.webauthn4jmicronaut.repo;

import io.github.baylorpaul.webauthn4jmicronaut.entity.PasskeyChallenge;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.data.annotation.Query;
import io.micronaut.data.jdbc.annotation.JdbcRepository;
import io.micronaut.data.model.query.builder.sql.Dialect;
import io.micronaut.data.repository.PageableRepository;

import java.util.Optional;
import java.util.UUID;

@JdbcRepository(dialect = Dialect.POSTGRES)
public interface PasskeyChallengeRepository extends PageableRepository<PasskeyChallenge, UUID> {

	/** Find the non-expired challenge by session ID */
	@Query("SELECT pc.* FROM public.passkey_challenge pc WHERE pc.session_id = :sessionId AND pc.challenge_expiration >= current_timestamp")
	Optional<PasskeyChallenge> findNonExpiredBySessionId(@Parameter("sessionId") @NonNull UUID sessionId);

	/** Delete any expired challenges */
	@Query("DELETE FROM public.passkey_challenge WHERE challenge_expiration < current_timestamp")
	void deleteWhereExpired();
}
