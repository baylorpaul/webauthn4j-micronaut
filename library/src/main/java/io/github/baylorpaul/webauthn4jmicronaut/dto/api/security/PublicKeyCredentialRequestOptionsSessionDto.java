package io.github.baylorpaul.webauthn4jmicronaut.dto.api.security;

import com.webauthn4j.data.PublicKeyCredentialRequestOptions;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.ReflectiveAccess;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.UUID;

/**
 * Passkey/WebAuthn public key credential request options and a challenge session ID
 */
@Getter
@Serdeable
@ReflectiveAccess
@AllArgsConstructor
public class PublicKeyCredentialRequestOptionsSessionDto {
	/** The challenge session ID, used during authentication verification */
	private @NonNull @NotBlank UUID challengeSessionId;
	private @NonNull PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions;
}
