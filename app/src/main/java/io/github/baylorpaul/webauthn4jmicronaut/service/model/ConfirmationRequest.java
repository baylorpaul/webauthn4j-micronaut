package io.github.baylorpaul.webauthn4jmicronaut.service.model;

import io.github.baylorpaul.webauthn4jmicronaut.service.model.enums.ConfirmationType;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import lombok.Builder;
import lombok.Data;

import java.util.Map;

@Data
@Builder
public class ConfirmationRequest {
	/** the type of confirmation request */
	private @NonNull ConfirmationType type;
	/** the email address of the user who will make the confirmation */
	private @NonNull String email;
	/** null for no expiration, else the number of seconds until the confirmation token expires */
	private @Nullable Integer expirationSeconds;
	/** additional JWT claims, or null for none */
	private @Nullable Map<String, Object> additionalJwtClaims;
}
