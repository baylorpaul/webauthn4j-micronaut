package io.github.baylorpaul.webauthn4jmicronaut.controller;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.verifier.exception.VerificationException;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.PublicKeyCredentialCreationOptionsSessionDto;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.PublicKeyCredentialRequestOptionsSessionDto;
import io.github.baylorpaul.webauthn4jmicronaut.security.PasskeyService;
import io.github.baylorpaul.webauthn4jmicronaut.security.model.PasskeyChallengeAndUserHandle;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.annotation.ReflectiveAccess;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.*;
import io.micronaut.http.exceptions.HttpStatusException;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.serde.annotation.SerdeImport;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.inject.Inject;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.UUID;

/**
 * @see <a href="https://github.com/webauthn4j/webauthn4j">WebAuthn4J</a>
 * @see <a href="https://smartyr.me/blog/testing-passkeys-webauthn-with-spring/">Testing Passkeys / WebAuthn with Spring</a>
 * @see <a href="https://docs.spring.io/spring-security/reference/servlet/authentication/passkeys.html">Compare to Spring Security Passkeys, which uses X-CSRF-TOKEN</a>
 */
@SerdeImport.Repeated({
		@SerdeImport(PublicKeyCredentialCreationOptions.class),
		@SerdeImport(PublicKeyCredentialRpEntity.class),
		@SerdeImport(PublicKeyCredentialUserEntity.class),
		@SerdeImport(PublicKeyCredentialDescriptor.class),
		@SerdeImport(DefaultChallenge.class),
		@SerdeImport(PublicKeyCredentialParameters.class),
		@SerdeImport(PublicKeyCredentialType.class),
		@SerdeImport(COSEAlgorithmIdentifier.class),
		@SerdeImport(AuthenticatorSelectionCriteria.class),
		@SerdeImport(PublicKeyCredentialHints.class),
		@SerdeImport(AuthenticatorAttachment.class),
		@SerdeImport(AuthenticatorTransport.class),
		@SerdeImport(AuthenticationExtensionsClientInputs.class),
		@SerdeImport(ResidentKeyRequirement.class),
		@SerdeImport(UserVerificationRequirement.class),
		@SerdeImport(AttestationConveyancePreference.class),
		@SerdeImport(PublicKeyCredentialRequestOptions.class)
})
@ExecuteOn(TaskExecutors.IO)
@Controller("/passkeys")
public class PasskeyController {

	private static final Logger log = LoggerFactory.getLogger(PasskeyController.class);

	@Inject
	private PasskeyService passkeyService;

	@Data
	@Serdeable
	@ReflectiveAccess
	@NoArgsConstructor
	@AllArgsConstructor
	public static class PasskeyVerification {
		private boolean verified;
	}

	/**
	 * GET WebAuthn passkey registration / attestation options. The important part is that the challenge is returned,
	 * while the rest is a convenience, so the client does not need to generate it.
	 * The WebAuthn specification does not define a specific method for passing the challenge from the backend server to
	 * the frontend. You could embed it in an HTML page or set up a REST endpoint to return the challenge. Another good
	 * idea is to create an endpoint that returns the entire PublicKeyCredentialCreationOptions.
	 * @see <a href="https://webauthn4j.github.io/webauthn4j/en/#generating-a-webauthn-credential-key-pair">Generating a WebAuthn credential key pair</a>
	 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions#creating_a_public_key_credential">Creating a public key credential</a>
	 * @see <a href="https://simplewebauthn.dev/docs/packages/server#1-generate-registration-options">Generate registration options</a>
	 * @see <a href="https://developers.google.com/identity/passkeys/developer-guides/server-registration#create_credential_creation_options">Create credential creation options</a>
	 */
	@Secured(SecurityRule.IS_ANONYMOUS) // no security
	@Get("/methods/generateRegistrationOptions")
	public PublicKeyCredentialCreationOptionsSessionDto generateRegistrationOptions(
			@NotBlank String uniqueNameOrEmail,
			@Nullable String displayName
	) {
		return passkeyService.generateRegistrationOptionsAndSaveChallenge(uniqueNameOrEmail, displayName);
	}

	/**
	 * POST the WebAuthn passkey registration response
	 * @param challengeSessionId the session ID associated with the recently issued challenge. This is required because
	 *            the API does not retain a session to link the generated registration options to the verification.
	 * @see <a href="https://developers.google.com/identity/passkeys/developer-guides/server-registration#store_the_public_key">Store the public key</a>
	 */
	@Secured(SecurityRule.IS_ANONYMOUS) // no security
	@Post("/methods/verifyRegistration")
	public PasskeyVerification verifyRegistration(
			@NonNull @Header("X-Challenge-Session-ID") UUID challengeSessionId,
			@NonNull @Body String registrationResponseJSON
	) {
		WebAuthnManager webAuthnManager = createWebAuthnManager();

		RegistrationData registrationData;
		try {
			registrationData = webAuthnManager.parseRegistrationResponseJSON(registrationResponseJSON);
		} catch (DataConversionException e) {
			// Caught a WebAuthn data structure parse error
			throw new HttpStatusException(HttpStatus.BAD_REQUEST, "unexpected data structure");
		}

		PasskeyChallengeAndUserHandle challengeAndUserHandle = passkeyService.findNonNullChallengeAndDiscard(challengeSessionId);
		String userHandleBase64Url = challengeAndUserHandle.getUserHandleBase64Url();
		if (userHandleBase64Url == null) {
			throw new HttpStatusException(HttpStatus.UNAUTHORIZED, "Challenge is not associated with a user handle ID");
		}

		Challenge savedRegistrationChallenge = challengeAndUserHandle.getChallenge();
		RegistrationParameters registrationParameters = passkeyService.loadRegistrationParametersForVerification(registrationData, savedRegistrationChallenge);

		try {
			// The challenge will be verified here
			webAuthnManager.verify(registrationData, registrationParameters);
		} catch (VerificationException e) {
			// Caught a WebAuthn data verification error
			log.warn("Invalid passkey credentials while verifying registration: {}", e.getMessage());
			throw new HttpStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
		}

		// You may create your own CredentialRecord implementation to save friendly authenticator name
		CredentialRecord credentialRecord = new CredentialRecordImpl(
				registrationData.getAttestationObject(),
				registrationData.getCollectedClientData(),
				registrationData.getClientExtensions(),
				registrationData.getTransports()
		);
		// Persist the credential record, and associate it with the user handle. This may be for a new or existing user.
		// The credential record will be needed during the authentication process.
		passkeyService.saveCredential(userHandleBase64Url, credentialRecord);

		return new PasskeyVerification(true);
	}

	/**
	 * GET WebAuthn passkey authentication options
	 * @see <a href="https://developers.google.com/identity/passkeys/developer-guides/server-authentication#create_credential_request_options">Create credential request options</a>
	 */
	@Secured(SecurityRule.IS_ANONYMOUS) // no security
	@Get("/methods/generateAuthenticationOptions")
	public PublicKeyCredentialRequestOptionsSessionDto generateAuthenticationOptions() {
		return passkeyService.generateAuthenticationOptionsAndSaveChallenge();
	}

	/**
	 * POST the WebAuthn passkey authentication response
	 * @see <a href="https://developers.google.com/identity/passkeys/developer-guides/server-authentication#verify_and_sign_in_the_user">Verify and sign in the user</a>
	 */
	@Secured(SecurityRule.IS_ANONYMOUS) // no security
	@Post("/methods/verifyAuthentication")
	public PasskeyVerification verifyAuthentication(
			@NonNull @Header("X-Challenge-Session-ID") UUID challengeSessionId,
			@NonNull @Body String authenticationResponseJSON
	) {
		WebAuthnManager webAuthnManager = createWebAuthnManager();

		AuthenticationData authenticationData;
		try {
			authenticationData = webAuthnManager.parseAuthenticationResponseJSON(authenticationResponseJSON);
		} catch (DataConversionException e) {
			// Caught a WebAuthn data structure parse error
			throw new HttpStatusException(HttpStatus.BAD_REQUEST, "unexpected data structure");
		}

		final AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = authenticationData.getAuthenticatorData();
		if (authenticatorData == null) {
			throw new HttpStatusException(HttpStatus.UNAUTHORIZED, "invalid authenticator data");
		}

		PasskeyChallengeAndUserHandle challengeAndUserHandle = passkeyService.findNonNullChallengeAndDiscard(challengeSessionId);
		Challenge savedAuthenticationChallenge = challengeAndUserHandle.getChallenge();

		AuthenticationParameters authenticationParameters = passkeyService.loadAuthenticationParametersForVerification(authenticationData, savedAuthenticationChallenge);

		try {
			// The challenge will be verified here
			webAuthnManager.verify(authenticationData, authenticationParameters);
		} catch (VerificationException e) {
			// Caught a WebAuthn data validation error
			log.warn("Invalid passkey credentials while verifying authentication: {}", e.getMessage());
			throw new HttpStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials and/or signature");
		}

		// Update the counter of the authenticator record
		passkeyService.updateCounter(authenticationData.getCredentialId(), authenticatorData.getSignCount());

// TODO return a User object instead, or whatever is necessary to log the user in
		return new PasskeyVerification(true);
	}

	/**
	 * Create a WebAuthnManager. Since most sites don’t require strict attestation statement verification, WebAuthn4J
	 * provides WebAuthnManager.createNonStrictWebAuthnManager factory method that returns an WebAuthnManager instance
	 * configured AttestationStatementVerifier and CertPathTrustworthinessVerifier not to verify attestation statements.
	 * @see <a href="https://webauthn4j.github.io/webauthn4j/en/#configuration">WebAuthn4J Configuration</a>
	 */
	private static WebAuthnManager createWebAuthnManager() {
/* TODO we can pass an ObjectConverter if we'd like. Do we need a custom ObjectConverter?
ObjectMapper jsonMapper = new ObjectMapper();
jsonMapper.registerModule(new WebAuthnMetadataJSONModule());
jsonMapper.registerModule(new WebAuthn4JSpringSecurityJSONModule());
ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
new ObjectConverter(jsonMapper, cborMapper);
*/
		return WebAuthnManager.createNonStrictWebAuthnManager();
	}
}
