package io.github.baylorpaul.webauthn4jmicronaut.entity;

import io.github.baylorpaul.micronautjsonapi.identifiable.JsonApiResourceable;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.ReflectiveAccess;
import io.micronaut.data.annotation.GeneratedValue;
import io.micronaut.data.annotation.Id;
import io.micronaut.data.annotation.MappedEntity;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@MappedEntity
@Data
@Builder(toBuilder = true)
@Serdeable.Deserializable
@NoArgsConstructor
@AllArgsConstructor
@ReflectiveAccess
public class User implements JsonApiResourceable {
	@Override
	public String toResourceType() {
		return "user";
	}

	private @Id @GeneratedValue @NonNull long id;
	private @NotBlank String email;
	private @NotBlank String name;
	private boolean enabled;
	private @GeneratedValue Instant created;
	private @GeneratedValue Instant updated;
}
