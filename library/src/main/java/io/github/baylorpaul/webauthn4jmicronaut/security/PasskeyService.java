package io.github.baylorpaul.webauthn4jmicronaut.security;

import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.client.challenge.Challenge;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.PublicKeyCredentialCreationOptionsSessionDto;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.PublicKeyCredentialRequestOptionsSessionDto;
import io.github.baylorpaul.webauthn4jmicronaut.security.model.AuthenticationUserInfo;
import io.github.baylorpaul.webauthn4jmicronaut.security.model.PasskeyChallengeAndUserHandle;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.exceptions.HttpStatusException;
import jakarta.validation.constraints.NotBlank;

import java.util.UUID;

public interface PasskeyService<C, V> {

	/**
	 * Generate registration options, persist the challenge, and generate a session ID for registration verification
	 * @throws HttpStatusException if the registration options could not be generated
	 */
	@NonNull
	PublicKeyCredentialCreationOptionsSessionDto generateRegistrationOptionsAndSaveChallenge(
			@NotBlank String uniqueNameOrEmail, @Nullable String displayName
	) throws HttpStatusException;

	/**
	 * Generate passkey creation options for adding a passkey to an existing user and persist the challenge
	 * @param token the short-lived token that was recently issued to the user
	 * @throws HttpStatusException if the creation options could not be generated
	 */
	@NonNull PublicKeyCredentialCreationOptionsSessionDto generateCreationOptionsForExistingAccountAndSaveChallenge(
			@NotBlank String token
	) throws HttpStatusException;

	/**
	 * Generate passkey creation options for adding a passkey to an existing user that is authenticated, and persist the
	 * challenge
	 * @param userVerification information that re-verifies user identity
	 * @throws HttpStatusException if the creation options could not be generated
	 */
	@NonNull PublicKeyCredentialCreationOptionsSessionDto generateCreationOptionsForUserAndSaveChallenge(
			@NonNull String userHandleBase64Url, @NonNull V userVerification
	) throws HttpStatusException;

	/**
	 * Find the non-expired challenge and discard/delete it from persistence. Discarding the challenge is important to
	 * prevent replay attacks.
	 * @param challengeSessionId the session ID
	 * @return the non-null challenge that was previously issued. This challenge will have been removed from persistence upon return
	 * @throws HttpStatusException if the challenge could not be found or was expired
	 */
	@NonNull
	PasskeyChallengeAndUserHandle findNonNullChallengeAndDiscard(@NonNull UUID challengeSessionId) throws HttpStatusException;

	/**
	 * For verification, load the registration parameters.
	 * @param registrationData the registration data
	 * @param savedRegistrationChallenge the server-generated challenge that was issued when the registration options where created
	 * @throws HttpStatusException if the challenge or other part of the registration parameters could not be retrieved
	 */
	@NonNull
	RegistrationParameters loadRegistrationParametersForVerification(
			@NonNull RegistrationData registrationData, @NonNull Challenge savedRegistrationChallenge
	) throws HttpStatusException;

	/**
	 * Persist the credentials after the passkey has been verified. And associate the credential with the user handle
	 * ID. If the user handle ID is not yet associated with a user, create the user.
	 * @param userHandleBase64Url the user handle, encoded in Base64Url. This is required because the API does not retain
	 *            any session to link the generated registration options to the verification.
	 * @return the saved credential
	 * @throws HttpStatusException if the credentials could not be persisted
	 */
	C saveCredential(@NonNull String userHandleBase64Url, @NonNull CredentialRecord credentialRecord) throws HttpStatusException;

	/**
	 * Generate authentication options, persist the challenge, and generate a session ID for authentication verification
	 * @param userHandleBase64Url null if the user is not authenticated, else the user handle, encoded in Base64Url. If
	 *            provided, this may be used to provide additional information, such as "allowCredentials" values.
	 * @throws HttpStatusException if the authentication options could not be generated
	 */
	@NonNull
	PublicKeyCredentialRequestOptionsSessionDto generateAuthenticationOptionsAndSaveChallenge(
			@Nullable String userHandleBase64Url
	) throws HttpStatusException;

	/**
	 * For verification, load the authentication parameters.
	 * @param authenticationData the authentication data
	 * @param savedAuthenticationChallenge the server-generated challenge that was issued when the authentication options where created
	 * @throws HttpStatusException if the challenge or other part of the authentication parameters could not be retrieved
	 */
	@NonNull
	AuthenticationParameters loadAuthenticationParametersForVerification(
			@NonNull AuthenticationData authenticationData, @NonNull Challenge savedAuthenticationChallenge
	) throws HttpStatusException;

	/**
	 * Update the credential record counter
	 * @throws HttpStatusException if the credentials could not be updated
	 */
	void updateCounter(byte[] credentialId, long counter) throws HttpStatusException;

	/**
	 * Find a user handle for an existing user, optionally creating it if it does not exist
	 * @param generateIfNotFound true if the handle should be generated if it does not exist
	 * @return the user handle, encoded in Base64Url
	 * @throws HttpStatusException if the user handle or user does not exist, and the option to create it was false
	 */
	@NonNull String findUserHandleBase64Url(
			@NonNull String userId, boolean generateIfNotFound
	) throws HttpStatusException;

	/**
	 * Generate user info for a credential ID
	 * @return null if the credential ID could not be mapped to a user, else the user info
	 */
	@Nullable
	AuthenticationUserInfo generateAuthenticationUserInfo(byte[] credentialId);

	/**
	 * Remove expired challenges and unattached user handles.
	 * Delete all expired passkey challenges, which may or may not have a passkey user handle.
	 * Then delete all passkey user handle records that have neither a user ID nor an unexpired challenge.
	 * We do not delete passkey user handle records associated with a user because we want to retain the "userHandle"
	 * value for future use.
	 */
	void deleteExpiredChallengesAndPasskeyUserHandles();
}
