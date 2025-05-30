package io.github.baylorpaul.webauthn4jmicronaut.service;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.data.jdbc.runtime.JdbcOperations;
import io.micronaut.transaction.TransactionDefinition;
import io.micronaut.transaction.annotation.Transactional;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Singleton
@Transactional
public class LockService {

	@Inject
	private JdbcOperations jdbcOperations;

	@Getter
	@AllArgsConstructor
	public enum AdvisoryLockType {
		/** For finding and invalidating utilized confirmation tokens for a user */
		UTILIZED_CONFIRMATION_TOKEN_USER(1),
		;

		/** the first of two keys for the advisory lock */
		private final int key1;
	}

	/**
	 * Obtain an exclusive transaction-level advisory lock, waiting if necessary.
	 * @param advisoryLockType the lock type, which provides the first of two keys for the advisory lock
	 * @param key2 the second of two keys for the advisory lock
	 */
	@Transactional(propagation = TransactionDefinition.Propagation.MANDATORY)
	public void advisoryLockExclusiveTxn(@NonNull AdvisoryLockType advisoryLockType, int key2) {
		jdbcOperations.prepareStatement(
				"SELECT pg_advisory_xact_lock(?, ?)",
				stmt -> {
					stmt.setInt(1, advisoryLockType.getKey1());
					stmt.setInt(2, key2);
					stmt.executeQuery();
					return null;
				}
		);
	}
}
