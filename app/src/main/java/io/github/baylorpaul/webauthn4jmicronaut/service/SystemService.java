package io.github.baylorpaul.webauthn4jmicronaut.service;

import io.micronaut.data.jdbc.runtime.JdbcOperations;
import io.micronaut.transaction.annotation.Transactional;
import jakarta.inject.Singleton;
import lombok.AllArgsConstructor;

import java.sql.ResultSet;
import java.time.Instant;

@Singleton
@Transactional
@AllArgsConstructor
public class SystemService {

	private final JdbcOperations jdbcOperations;

	public Instant getNow() {
		final String sql = "SELECT current_timestamp";
		return jdbcOperations.prepareStatement(sql, stmt -> {
			ResultSet rs = stmt.executeQuery();
			rs.next();
			return rs.getTimestamp(1).toInstant();
		});
	}
}
