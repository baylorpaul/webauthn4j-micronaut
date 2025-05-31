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
import io.github.baylorpaul.micronautjsonapi.identifiable.JsonApiResourceable;
import io.github.baylorpaul.micronautjsonapi.model.JsonApiObject;
import io.github.baylorpaul.micronautjsonapi.model.JsonApiPage;
import io.github.baylorpaul.micronautjsonapi.model.JsonApiResource;
import io.github.baylorpaul.micronautjsonapi.model.JsonApiTopLevelResource;
import io.github.baylorpaul.micronautjsonapi.util.JsonApiUtil;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.PublicKeyCredentialCreationOptionsSessionDto;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.PublicKeyCredentialRequestOptionsSessionDto;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.serialization.PasskeyEntityByteArrayIdMixin;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.submission.UserVerificationDto;
import io.github.baylorpaul.webauthn4jmicronaut.entity.PasskeyCredentials;
import io.github.baylorpaul.webauthn4jmicronaut.entity.User;
import io.github.baylorpaul.webauthn4jmicronaut.repo.PasskeyCredentialsRepository;
import io.github.baylorpaul.webauthn4jmicronaut.repo.UserRepository;
import io.github.baylorpaul.webauthn4jmicronaut.rest.PasskeyRestService;
import io.github.baylorpaul.webauthn4jmicronaut.security.AuthenticationProviderForPreVerifiedCredentials;
import io.github.baylorpaul.webauthn4jmicronaut.security.PasskeyService;
import io.github.baylorpaul.webauthn4jmicronaut.security.SecurityUtil;
import io.github.baylorpaul.webauthn4jmicronaut.security.model.AuthenticationUserInfo;
import io.github.baylorpaul.webauthn4jmicronaut.security.model.PasskeyChallengeAndUserHandle;
import io.github.baylorpaul.webauthn4jmicronaut.service.UserSecurityService;
import io.github.baylorpaul.webauthn4jmicronaut.service.UserService;
import io.github.baylorpaul.webauthn4jmicronaut.util.PasskeyUtil;
import io.micronaut.core.annotation.Introspected;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.async.annotation.SingleResult;
import io.micronaut.data.model.Page;
import io.micronaut.data.model.Pageable;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.*;
import io.micronaut.http.exceptions.HttpStatusException;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.handlers.LoginHandler;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.serde.annotation.SerdeImport;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.inject.Inject;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.security.Principal;
import java.util.Optional;
import java.util.UUID;

/**
 * @see <a href="https://github.com/webauthn4j/webauthn4j">WebAuthn4J</a>
 * @see <a href="https://smartyr.me/blog/testing-passkeys-webauthn-with-spring/">Testing Passkeys / WebAuthn with Spring</a>
 * @see <a href="https://docs.spring.io/spring-security/reference/servlet/authentication/passkeys.html">Compare to Spring Security Passkeys, which uses X-CSRF-TOKEN</a>
 */
@SerdeImport.Repeated({
		@SerdeImport(PublicKeyCredentialCreationOptions.class),
		@SerdeImport(PublicKeyCredentialRpEntity.class),
		@SerdeImport(
				value = PublicKeyCredentialUserEntity.class,
				// Serialize the byte array ID to a Base64Url string, instead of a JSON number[]
				mixin = PasskeyEntityByteArrayIdMixin.class
		),
		@SerdeImport(
				value = PublicKeyCredentialDescriptor.class,
				// Serialize the byte array ID to a Base64Url string, instead of a JSON number[]
				mixin = PasskeyEntityByteArrayIdMixin.class
		),
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
	private PasskeyCredentialsRepository passkeyCredentialsRepo;

	@Inject
	private PasskeyRestService passkeyRestService;

	@Inject
	private PasskeyService<JsonApiTopLevelResource, UserVerificationDto> passkeyService;

	@Inject
	private LoginHandler<HttpRequest<?>, MutableHttpResponse<?>> loginHandler;

	@Inject
	private UserRepository userRepo;

	@Inject
	private UserService userService;

	@Inject
	private UserSecurityService userSecurityService;

	@Secured(SecurityRule.IS_AUTHENTICATED)
	@Get
	public JsonApiPage<PasskeyCredentials> getPasskeys(Principal principal, @Valid Pageable pageable) {
		long userId = SecurityUtil.requireUserId(principal);
		final Page<PasskeyCredentials> page = passkeyCredentialsRepo.findByUserIdEqualsOrderById(userId, pageable);
		return new JsonApiPage<>(page, null);
	}

	@Secured(SecurityRule.IS_AUTHENTICATED)
	@Get("/{id}")
	public JsonApiTopLevelResource show(long id, Principal principal) {
		return passkeyCredentialsRepo.findByIdAndUserId(id, SecurityUtil.requireUserId(principal))
				.map(JsonApiResourceable::toTopLevelResource)
				.orElseThrow(() -> new HttpStatusException(HttpStatus.NOT_FOUND, "Passkey not found"));
	}

	@Secured(SecurityRule.IS_AUTHENTICATED)
	@Patch("/{id}")
	public Optional<JsonApiTopLevelResource> update(
			long id,
			Principal principal,
			@Body JsonApiObject<JsonApiResource> body
	) {
		return JsonApiUtil.readAndValidateLongId(body, id)
				.flatMap(bodyId -> passkeyCredentialsRepo.findByIdAndUserId(id, SecurityUtil.requireUserId(principal)))
				.map(pc -> passkeyRestService.updatePasskey(pc, body.getData()))
				.map(JsonApiResourceable::toTopLevelResource);
	}

	@Secured(SecurityRule.IS_AUTHENTICATED)
	@Delete("/{id}")
	public HttpResponse<?> delete(long id, Principal principal) {
		return passkeyCredentialsRepo.findByIdAndUserId(id, SecurityUtil.requireUserId(principal))
				.map(pc -> {
					passkeyCredentialsRepo.delete(pc);
					return HttpResponse.noContent();
				})
				.orElse(HttpResponse.notFound());
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

	@Data
	@Serdeable
	@Introspected
	public static class RegistrationOptionsForExistingAccountDto {
		/** the short-lived token that was recently issued to the user */
		private @NotBlank String token;
	}

	/**
	 * GET WebAuthn passkey registration / attestation options for adding to an existing account. The user account is
	 * determined via the token provided, which was recently emailed to the user.
	 */
	@Secured(SecurityRule.IS_ANONYMOUS) // no security
	@Post("/methods/generateRegistrationOptionsForExistingAccount")
	public PublicKeyCredentialCreationOptionsSessionDto generateRegistrationOptionsForExistingAccount(
			@Body RegistrationOptionsForExistingAccountDto regOpts
	) {
		return passkeyService.generateRegistrationOptionsForExistingAccountAndSaveChallenge(regOpts.getToken());
	}

	/**
	 * POST to get WebAuthn passkey registration / attestation options for adding to an authenticated user's account.
	 * This is a POST instead of a GET because it contains sensitive information for re-verifying the account.
	 */
	@Secured(SecurityRule.IS_AUTHENTICATED)
	@Post("/methods/generateRegistrationOptionsAsAuthenticatedUser")
	public PublicKeyCredentialCreationOptionsSessionDto generateRegistrationOptionsAsAuthenticatedUser(
			Principal principal, @Body UserVerificationDto userVerificationDto
	) {
		long userId = SecurityUtil.requireUserId(principal);
		String userHandleBase64Url = passkeyService.findUserHandleBase64Url(String.valueOf(userId), true);
		return passkeyService.generateRegistrationOptionsForUserAndSaveChallenge(userHandleBase64Url, userVerificationDto);
	}

	/**
	 * POST the WebAuthn passkey registration response, whether for a new user or an existing user.
	 * @param challengeSessionId the session ID associated with the recently issued challenge. This is required because
	 *            the API does not retain a session to link the generated registration options to the verification.
	 * @return the saved credential
	 * @see <a href="https://developers.google.com/identity/passkeys/developer-guides/server-registration#store_the_public_key">Store the public key</a>
	 */
	@Secured(SecurityRule.IS_ANONYMOUS) // no security
	@Post("/methods/verifyRegistration")
	@Status(HttpStatus.CREATED)
	public JsonApiTopLevelResource verifyRegistration(
			@NonNull @Header("X-Challenge-Session-ID") UUID challengeSessionId,
			@NonNull @Body String registrationResponseJSON
	) {
		WebAuthnManager webAuthnManager = PasskeyUtil.createWebAuthnManager();

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
		return passkeyService.saveCredential(userHandleBase64Url, credentialRecord);
	}

	/**
	 * GET WebAuthn passkey authentication options
	 * @see <a href="https://developers.google.com/identity/passkeys/developer-guides/server-authentication#create_credential_request_options">Create credential request options</a>
	 */
	@Secured(SecurityRule.IS_ANONYMOUS) // no security
	@Get("/methods/generateAuthenticationOptions")
	public PublicKeyCredentialRequestOptionsSessionDto generateAuthenticationOptions() {
		return passkeyService.generateAuthenticationOptionsAndSaveChallenge(null);
	}

	/**
	 * GET WebAuthn passkey authentication options as an already authenticated user.
	 * The authentication options shall include "allowCredentials" values, if available.
	 * @see <a href="https://developers.google.com/identity/passkeys/developer-guides/server-authentication#create_credential_request_options">Create credential request options</a>
	 */
	@Secured(SecurityRule.IS_AUTHENTICATED)
	@Get("/methods/generateAuthenticationOptionsAsAuthenticatedUser")
	public PublicKeyCredentialRequestOptionsSessionDto generateAuthenticationOptionsAsAuthenticatedUser(Principal principal) {
		long userId = SecurityUtil.requireUserId(principal);
		String userHandleBase64Url = passkeyService.findUserHandleBase64Url(String.valueOf(userId), false);
		return passkeyService.generateAuthenticationOptionsAndSaveChallenge(userHandleBase64Url);
	}

	/**
	 * POST the WebAuthn passkey authentication response.
	 * @return a JWT access token, refresh token, etc.
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.4">Access Token Response</a>
	 * @see <a href="https://developers.google.com/identity/passkeys/developer-guides/server-authentication#verify_and_sign_in_the_user">Verify and sign in the user</a>
	 */
	@Secured(SecurityRule.IS_ANONYMOUS) // no security
	@Post("/methods/verifyAuthenticationForAccessTokenResponse")
	@SingleResult
	public Mono<MutableHttpResponse<?>> verifyAuthenticationForAccessTokenResponse(
			@NonNull @Header("X-Challenge-Session-ID") UUID challengeSessionId,
			@NonNull @Body String authenticationResponseJSON,
			HttpRequest<?> request
	) {
		try {
			AuthenticationUserInfo userInfo = verifyAuthentication(challengeSessionId, authenticationResponseJSON);

			Mono<MutableHttpResponse<?>> result = createJwtAccessKey(userInfo, request);
			return result;
		} catch (HttpStatusException e) {
			userSecurityService.publishLoginFailed(null, AuthenticationResponse.failure(e.getMessage()), request);
			throw e;
		}
	}

	/**
	 * POST the WebAuthn passkey authentication response as an already authenticated user. The reason this method
	 * requires authentication is NOT for security purposes. It is a courtesy so that the requestor can be notified
	 * earlier in the confirmation token process if they have provided a passkey for a different user than the one for
	 * which they intend to use the confirmation token.
	 * @param principal the authenticated user. Because the objective of this method is to verify passkey
	 *            authentication, the "principal" is not absolutely required in theory, but this method is intended to
	 *            only be used for users that are already authenticated.
	 * @return a short-lived "passkey access verified" JWT confirmation token. This may be used to take a protected
	 *         action that requires confirming user access. E.g. adding an integration token, changing a user's
	 *         password, or adding another passkey to the user's account.
	 */
	@Secured(SecurityRule.IS_AUTHENTICATED)
	@Post("/methods/verifyAuthenticationAsAuthenticatedUserForConfirmationTokenResponse")
	public String verifyAuthenticationAsAuthenticatedUserForConfirmationTokenResponse(
			Principal principal,
			@NonNull @Header("X-Challenge-Session-ID") UUID challengeSessionId,
			@NonNull @Body String authenticationResponseJSON,
			HttpRequest<?> request
	) {
		long expectedUserId = SecurityUtil.requireUserId(principal);

		return generateConfirmationToken(challengeSessionId, authenticationResponseJSON, expectedUserId, request);
	}

	/**
	 * A less-preferred method to POST the WebAuthn passkey authentication response without being an authenticated user.
	 * This means that the courtesy check to ensure a passkey was provided for the appropriate user will not occur. If a
	 * passkey for the wrong user is selected, the requestor will encounter the error later in the process when they try
	 * to use the confirmation token.
	 * One use case for this instead of using the "authenticated" method is if a pre-existing user tries to login with a
	 * federated login for the first time. To associate the federated login with the user, additional verification is
	 * required, such as via passkey or password. Since the user isn't already authenticated by other means, this is an
	 * appropriate method to use to verify the passkey authentication in exchange for a confirmation token.
	 * @return a short-lived "passkey access verified" JWT confirmation token. This may be used to take a protected
	 *         action that requires confirming user access. E.g. associating a federated login with a pre-existing user,
	 *         adding an integration token, changing a user's password, or adding another passkey to the user's account.
	 */
	@Secured(SecurityRule.IS_ANONYMOUS) // no security
	@Post("/methods/verifyAuthenticationForConfirmationTokenResponse")
	public String verifyAuthenticationForConfirmationTokenResponse(
			@NonNull @Header("X-Challenge-Session-ID") UUID challengeSessionId,
			@NonNull @Body String authenticationResponseJSON,
			HttpRequest<?> request
	) {
		// We'll be skipping the user ID courtesy check
		Long optionalExpectedUserId = null;

		return generateConfirmationToken(challengeSessionId, authenticationResponseJSON, optionalExpectedUserId, request);
	}

	/**
	 * Generate a passkey access verified confirmation token that allows for taking protected actions, such as
	 * associating a federated login with a pre-existing user, adding an integration token, changing a user's password,
	 * or adding another passkey to the user's account.
	 * An expected user ID may also be provided as a courtesy check, but it is not required and is NOT for security
	 * purposes. This courtesy check verifies that the requestor is using the correct passkey for the intended user, in
	 * case the requestor has passkeys for multiple users. If the expected user ID does not match the passkey
	 * authentication response, the request will be rejected. That is not because of a security concern but is a
	 * courtesy to the requestor in case they chose a passkey for the wrong user. This short-circuit courtesy ensures
	 * they will not continue through the process with the wrong confirmation token, only to get an error later on when
	 * they try to use the confirmation token for the wrong user.
	 * @param optionalExpectedUserId null for no user ID check, else the expected user ID to verify. This is for a
	 *            courtesy short-circuit verification, not security purposes.
	 */
	private String generateConfirmationToken(
			@NonNull UUID challengeSessionId, @NonNull String authenticationResponseJSON,
			@Nullable Long optionalExpectedUserId, HttpRequest<?> request
	) {
		try {
			AuthenticationUserInfo userInfo = verifyAuthentication(challengeSessionId, authenticationResponseJSON);
			if (userInfo == null) {
				throw new HttpStatusException(HttpStatus.UNAUTHORIZED, "No matching credentials");
			}

			final long userId;
			try {
				userId = Long.parseLong(userInfo.getUserId());
			} catch (NumberFormatException e) {
				throw new HttpStatusException(HttpStatus.BAD_REQUEST, "Unexpected user ID");
			}

			if (optionalExpectedUserId != null) {
				// Courtesy check that the user ID matches what we expect. This is NOT a security check, but notifies
				// the requestor of the mismatch earlier in the process, instead of waiting until they try to use the
				// confirmation token. If the requestor had first invoked
				// generateAuthenticationOptionsAsAuthenticatedUser(), then a user ID mismatch is not expected, since
				// "allowCredentials" would have been set, and their authenticator would only pick a valid passkey.
				if (userId != optionalExpectedUserId.longValue()) {
					// Ensure the credentials in the authentication response match the authenticated User
					throw new HttpStatusException(HttpStatus.FORBIDDEN, "Credentials for wrong user");
				}
			}

			User user = userRepo.findById(userId)
					.orElseThrow(() -> new HttpStatusException(HttpStatus.NOT_FOUND, "User not found"));

			String passkeyAccessVerifiedToken = userService.generatePasskeyAccessVerifiedConfirmationToken(user);
			return passkeyAccessVerifiedToken;
		} catch (RuntimeException e) {
			userSecurityService.publishLoginFailed(null, AuthenticationResponse.failure(e.getMessage()), request);
			throw e;
		}
	}

	/**
	 * Verify the WebAuthn passkey authentication response, and return the authentication user information.
	 * @return the credential ID for the passkey
	 * @throws HttpStatusException if the authentication fails verification
	 */
	private @Nullable AuthenticationUserInfo verifyAuthentication(
			UUID challengeSessionId, String authenticationResponseJSON
	) throws HttpStatusException {
		WebAuthnManager webAuthnManager = PasskeyUtil.createWebAuthnManager();

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

		byte[] credentialId = authenticationParameters.getAuthenticator().getAttestedCredentialData().getCredentialId();
		return passkeyService.generateAuthenticationUserInfo(credentialId);
	}

	/**
	 * After having verified the passkey credentials, generate a JWT access key for authentication.
	 */
	private Mono<MutableHttpResponse<?>> createJwtAccessKey(AuthenticationUserInfo userInfo, HttpRequest<?> request) {
		return AuthenticationProviderForPreVerifiedCredentials.generateAuthenticationResponseForPreVerifiedCredentials(userInfo)
				.map(authenticationResponse -> {
					// Similar to Micronaut Security's io.micronaut.security.endpoints.LoginController, except we're not
					// going to implement an HttpRequestAuthenticationProvider, since we don't want that to execute
					// under any other circumstances.

					if (authenticationResponse.isAuthenticated() && authenticationResponse.getAuthentication().isPresent()) {
						Authentication authentication = authenticationResponse.getAuthentication().get();
						userSecurityService.publishLoginSuccess(authentication, request);
						return loginHandler.loginSuccess(authentication, request);
					} else {
						log.warn("passkey login failed for userId: {}", userInfo == null ? null : userInfo.getUserId());

						userSecurityService.publishLoginFailed(
								userInfo == null ? null : new UserIdAuthenticationRequest(userInfo.getUserId(), null),
								authenticationResponse,
								request
						);

						return loginHandler.loginFailed(authenticationResponse, request);
					}
				})
				.switchIfEmpty(Mono.defer(() -> Mono.just(HttpResponse.status(HttpStatus.UNAUTHORIZED))));
	}

	@Getter
	@AllArgsConstructor
	private static class UserIdAuthenticationRequest implements AuthenticationRequest<String, String> {
		private String identity;
		private String secret;
	}
}
