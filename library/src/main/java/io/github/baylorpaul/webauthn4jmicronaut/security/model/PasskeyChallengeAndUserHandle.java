package io.github.baylorpaul.webauthn4jmicronaut.security.model;

import com.webauthn4j.data.client.challenge.Challenge;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Passkey/WebAuthn challenge and user handle
 */
@Getter
@AllArgsConstructor
public class PasskeyChallengeAndUserHandle {
	/** The challenge */
	private @NonNull Challenge challenge;
	/**
	 * The user handle, encoded in Base64Url. This will be null if authenticating, because the credential ID will be
	 * used instead
	 */
	private @Nullable String userHandleBase64Url;
}
