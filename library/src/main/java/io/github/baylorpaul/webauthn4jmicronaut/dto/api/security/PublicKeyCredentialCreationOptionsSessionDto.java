package io.github.baylorpaul.webauthn4jmicronaut.dto.api.security;

import com.webauthn4j.data.PublicKeyCredentialCreationOptions;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.ReflectiveAccess;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.UUID;

/**
 * Passkey/WebAuthn public key credential creation options and a challenge session ID
 */
@Getter
@Serdeable
@ReflectiveAccess
@AllArgsConstructor
public class PublicKeyCredentialCreationOptionsSessionDto {
	/** The challenge session ID, used during registration verification */
	private @NonNull @NotBlank UUID challengeSessionId;
	private @NonNull PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions;
}
