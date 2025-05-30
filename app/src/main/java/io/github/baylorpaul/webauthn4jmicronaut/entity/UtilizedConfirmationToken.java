package io.github.baylorpaul.webauthn4jmicronaut.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.github.baylorpaul.webauthn4jmicronaut.service.model.enums.ConfirmationType;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.data.annotation.GeneratedValue;
import io.micronaut.data.annotation.Id;
import io.micronaut.data.annotation.MappedEntity;
import io.micronaut.data.annotation.Relation;
import jakarta.validation.constraints.NotBlank;
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
public class UtilizedConfirmationToken {

	private @Id @GeneratedValue @NonNull long id;
	private @Relation(Relation.Kind.MANY_TO_ONE) User user;
	private ConfirmationType type;
	private @JsonIgnore @NonNull @NotBlank String utilizedToken;
	private @NonNull Instant expirationDate;
	private @GeneratedValue Instant created;
	private @GeneratedValue Instant updated;
}
