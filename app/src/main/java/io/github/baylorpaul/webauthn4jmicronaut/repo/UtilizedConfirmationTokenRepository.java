package io.github.baylorpaul.webauthn4jmicronaut.repo;

import io.github.baylorpaul.webauthn4jmicronaut.entity.UtilizedConfirmationToken;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.data.annotation.Query;
import io.micronaut.data.jdbc.annotation.JdbcRepository;
import io.micronaut.data.model.query.builder.sql.Dialect;
import io.micronaut.data.repository.PageableRepository;
import jakarta.validation.constraints.NotBlank;

import java.util.Optional;

@JdbcRepository(dialect = Dialect.POSTGRES)
public interface UtilizedConfirmationTokenRepository extends PageableRepository<UtilizedConfirmationToken, Long> {

	Optional<UtilizedConfirmationToken> findByUtilizedToken(@NonNull @NotBlank String utilizedToken);

	@Query("DELETE FROM public.utilized_confirmation_token WHERE expiration_date < current_timestamp")
	void deleteExpiredUtilizedConfirmationTokens();
}
