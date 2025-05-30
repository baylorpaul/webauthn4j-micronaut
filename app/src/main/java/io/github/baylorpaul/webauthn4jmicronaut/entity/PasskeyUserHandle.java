package io.github.baylorpaul.webauthn4jmicronaut.entity;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.data.annotation.GeneratedValue;
import io.micronaut.data.annotation.Id;
import io.micronaut.data.annotation.MappedEntity;
import io.micronaut.data.annotation.Relation;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@MappedEntity
@Data
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
public class PasskeyUserHandle {
	/**
	 * A random 64 byte ID, encoded in Base64Url, as the user handle. This ID never changes, does NOT match the user ID,
	 * and has no PII (Personally identifiable information).
	 */
	private @Id @NonNull String id;
	/** The user with which this handle is linked, if any */
	private @Nullable @Relation(Relation.Kind.ONE_TO_ONE) User user;
	private @Nullable String email;
	private @Nullable String name;
	private @GeneratedValue Instant created;
	private @GeneratedValue Instant updated;
}
