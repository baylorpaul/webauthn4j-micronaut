package io.github.baylorpaul.webauthn4jmicronaut.repo;

import io.github.baylorpaul.webauthn4jmicronaut.entity.PasskeyCredentials;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.data.annotation.Query;
import io.micronaut.data.jdbc.annotation.JdbcRepository;
import io.micronaut.data.model.Page;
import io.micronaut.data.model.Pageable;
import io.micronaut.data.model.query.builder.sql.Dialect;
import io.micronaut.data.repository.PageableRepository;
import io.micronaut.transaction.annotation.Transactional;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;

import java.util.List;
import java.util.Optional;

@AllArgsConstructor
@JdbcRepository(dialect = Dialect.POSTGRES)
public abstract class PasskeyCredentialsRepository implements PageableRepository<PasskeyCredentials, Long> {

	abstract public Optional<PasskeyCredentials> findByIdAndUserId(long id, long userId);

	abstract public Optional<PasskeyCredentials> findByCredentialId(@NonNull @NotBlank String base64UrlCredentialId);

	/** Find passkey credentials, if any, by the user handle, encoded in Base64Url */
	@Query("SELECT pc.* FROM public.passkey_user_handle puh JOIN public.passkey_credentials pc ON pc.user_id = puh.user_id WHERE puh.id = :userHandleBase64Url")
	abstract public List<PasskeyCredentials> findByUserHandle(@Parameter("userHandleBase64Url") @NonNull @NotBlank String userHandleBase64Url);

	@Transactional
	abstract public Page<PasskeyCredentials> findByUserIdEqualsOrderById(long userId, Pageable pageable);
}
