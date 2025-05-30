package io.github.baylorpaul.webauthn4jmicronaut.repo;

import io.github.baylorpaul.webauthn4jmicronaut.entity.User;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.data.annotation.Query;
import io.micronaut.data.jdbc.annotation.JdbcRepository;
import io.micronaut.data.model.query.builder.sql.Dialect;
import io.micronaut.data.repository.PageableRepository;
import io.micronaut.transaction.TransactionDefinition;
import io.micronaut.transaction.annotation.Transactional;
import jakarta.validation.constraints.NotBlank;

import java.util.Optional;

@JdbcRepository(dialect = Dialect.POSTGRES)
public interface UserRepository extends PageableRepository<User, Long> {

	Optional<User> findByEmail(@NonNull @NotBlank String email);

	@Transactional(propagation = TransactionDefinition.Propagation.REQUIRES_NEW)
	@Query("INSERT INTO public.user(email, name, enabled)" +
			" SELECT :email, :name, true" +
			" WHERE NOT EXISTS(SELECT id FROM public.user WHERE email = :email)")
	void saveUserIfNotExists(@NonNull @NotBlank String email, @NonNull @NotBlank String name);
}
