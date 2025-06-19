package io.github.baylorpaul.webauthn4jmicronaut.security.passkey.model;

import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import io.micronaut.core.annotation.NonNull;

/**
 * @param attestedCredentialDataIncludingPrivateKey the attested credential data, including the private key. Do NOT
 *            share the private key with the backend!
 * @param userHandleBase64Url The Base64URL encoded user handle
 */
public record PasskeyCredAndUserHandle(
		@NonNull AttestedCredentialData attestedCredentialDataIncludingPrivateKey,
		@NonNull String userHandleBase64Url
) {
}
