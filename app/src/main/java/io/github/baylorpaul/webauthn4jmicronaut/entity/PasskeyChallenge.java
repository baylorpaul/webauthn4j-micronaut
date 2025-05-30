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
import java.util.UUID;

@MappedEntity
@Data
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
public class PasskeyChallenge {
	private @Id @NonNull UUID sessionId;
	private @Nullable @Relation(Relation.Kind.MANY_TO_ONE) PasskeyUserHandle passkeyUserHandle;
	private @NonNull Instant challengeExpiration;
	private @NonNull String challenge;
	private @GeneratedValue Instant created;
	private @GeneratedValue Instant updated;
}
