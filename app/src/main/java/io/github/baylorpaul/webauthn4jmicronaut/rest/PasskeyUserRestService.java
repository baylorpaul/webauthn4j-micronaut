package io.github.baylorpaul.webauthn4jmicronaut.rest;

import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.data.*;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import io.github.baylorpaul.micronautjsonapi.model.JsonApiTopLevelResource;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.PublicKeyCredentialCreationOptionsSessionDto;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.PublicKeyCredentialRequestOptionsSessionDto;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.submission.UserVerificationDto;
import io.github.baylorpaul.webauthn4jmicronaut.entity.PasskeyChallenge;
import io.github.baylorpaul.webauthn4jmicronaut.entity.PasskeyCredentials;
import io.github.baylorpaul.webauthn4jmicronaut.entity.PasskeyUserHandle;
import io.github.baylorpaul.webauthn4jmicronaut.entity.User;
import io.github.baylorpaul.webauthn4jmicronaut.repo.PasskeyChallengeRepository;
import io.github.baylorpaul.webauthn4jmicronaut.repo.PasskeyCredentialsRepository;
import io.github.baylorpaul.webauthn4jmicronaut.repo.PasskeyUserHandleRepository;
import io.github.baylorpaul.webauthn4jmicronaut.repo.UserRepository;
import io.github.baylorpaul.webauthn4jmicronaut.security.PasskeyConfigurationProperties;
import io.github.baylorpaul.webauthn4jmicronaut.security.PasskeyService;
import io.github.baylorpaul.webauthn4jmicronaut.security.TokenUtil;
import io.github.baylorpaul.webauthn4jmicronaut.security.model.AuthenticationUserInfo;
import io.github.baylorpaul.webauthn4jmicronaut.security.model.PasskeyChallengeAndUserHandle;
import io.github.baylorpaul.webauthn4jmicronaut.security.model.PasskeyCredentialsPersistable;
import io.github.baylorpaul.webauthn4jmicronaut.service.SystemService;
import io.github.baylorpaul.webauthn4jmicronaut.util.ApiUtil;
import io.github.baylorpaul.webauthn4jmicronaut.util.PasskeyUtil;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.exceptions.HttpStatusException;
import io.micronaut.transaction.TransactionDefinition;
import io.micronaut.transaction.annotation.Transactional;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.validation.constraints.NotBlank;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Singleton
@Transactional
public class PasskeyUserRestService implements PasskeyService<JsonApiTopLevelResource, UserVerificationDto> {

	@Inject
	private PasskeyConfigurationProperties passkeyProps;

	@Inject
	private UserRestService userRestService;

	@Inject
	private PasskeyCredentialsRepository passkeyCredentialsRepo;

	@Inject
	private PasskeyUserHandleRepository passkeyUserHandleRepo;

	@Inject
	private PasskeyChallengeRepository passkeyChallengeRepo;

	@Inject
	private SecurityRestService securityRestService;

	@Inject
	private UserRepository userRepo;

	@Inject
	private SystemService systemService;

	private PublicKeyCredentialRpEntity buildPublicKeyCredentialRpEntity() {
		String rpId = passkeyProps.getRpId();
		String rpName = passkeyProps.getRpName();
		return new PublicKeyCredentialRpEntity(rpId, rpName);
	}

	/**
	 * The URL at which registrations and authentications should occur.
	 * 'http://localhost' and 'http://localhost:PORT' are also valid.
	 * Do NOT include any trailing /
	 */
	private Origin findOrigin() {
		return new Origin(passkeyProps.getOriginUrl());
	}

	/**
	 * @param previouslyIssuedChallenge the previously issued challenge to verify
	 */
	private ServerProperty buildServerPropertiesForVerification(Challenge previouslyIssuedChallenge) throws HttpStatusException {
		return PasskeyUtil.buildServerPropertiesForVerification(
				findOrigin(),
				passkeyProps.getRpId(),
				previouslyIssuedChallenge
		);
	}

	private static ObjectConverter findObjectConverter() {
		return new ObjectConverter();
	}

	private static AttestedCredentialDataConverter findAttestedCredentialDataConverter() {
		ObjectConverter objectConverter = findObjectConverter();
		return new AttestedCredentialDataConverter(objectConverter);
	}

	/**
	 * Map a "unique name or email" and "display name" into a PublicKeyCredentialUserEntity.
	 * @return a credential user entity record
	 * @throws HttpStatusException if the unique name or email is invalid, or another error occurs
	 * @see <a href="https://www.w3.org/TR/webauthn-1/#dictdef-publickeycredentialuserentity">User Account Parameters for Credential Generation (dictionary PublicKeyCredentialUserEntity)</a>
	 * @see <a href="https://www.w3.org/TR/webauthn-1/#sctn-user-handle-privacy">User Handle Contents</a>
	 * @see <a href="https://developers.google.com/identity/passkeys/developer-guides/server-authentication#verify_and_sign_in_the_user">Verify and sign in the user (optionally via userHandle)</a>
	 */
	private @NonNull PublicKeyCredentialUserEntity buildCredentialUserIfNotExists(
			@NotBlank String uniqueNameOrEmail, @Nullable String displayName
	) throws HttpStatusException {
		// We are NOT checking if the email already exists until the verification step when we create the user. That
		// way, it's not so easy to check a large list of email addresses, and whether they already exist.
		String formattedEmail = userRestService.formatEmailAndEnsureUniqueness(uniqueNameOrEmail, false);
		String formattedDisplayName = ApiUtil.buildAndValidateUserName(displayName, formattedEmail);

		byte[] userHandle = PasskeyUtil.generateUserHandle();

		// The PublicKeyCredentialUserEntity will be converted into a User once the registration is verified.
		// The "name" should be unique, and can be a username, email address, etc.
		// In our case, we're using an email address for "name".
		return new PublicKeyCredentialUserEntity(userHandle, formattedEmail, formattedDisplayName);
	}

	@Override
	public @NonNull PublicKeyCredentialCreationOptionsSessionDto generateRegistrationOptionsAndSaveChallenge(
			@NotBlank String uniqueNameOrEmail, @Nullable String displayName
	) throws HttpStatusException {
		PublicKeyCredentialUserEntity credUser = buildCredentialUserIfNotExists(uniqueNameOrEmail, displayName);

		// We just generated the "userHandle", so there will not be any associated PublicKeyCredentialDescriptor records
		// to "exclude".
		final List<PublicKeyCredentialDescriptor> excludeCredentials = null;

		// When generating passkey registration options, we'll have the email and display name, but not during
		// registration verification. The WebAuthn standard does not include this information in the credential data.
		// We'll only have the credential ID. So we'll need to persist this information now, and look it up when
		// registration is verified.

		// Store the challenge, associated with the user handle. Even though the timeout in the options is "just a hint"
		// to the browser, that is how long we will honor the challenge. It's a one-time use value, which is also discarded once used.
		Duration regTimeout = PasskeyUtil.REGISTRATION_TIMEOUT;
		PasskeyChallenge passkeyChallenge = savePasskeyUserHandleForNewUserWithChallenge(
				credUser,
				regTimeout.plus(5L, ChronoUnit.SECONDS)
		);

		PublicKeyCredentialRpEntity rp = buildPublicKeyCredentialRpEntity();
		Challenge challenge = new DefaultChallenge(passkeyChallenge.getChallenge());
		return new PublicKeyCredentialCreationOptionsSessionDto(
				passkeyChallenge.getSessionId(),
				PasskeyUtil.generateCreationOptions(rp, credUser, excludeCredentials, challenge, regTimeout)
		);
	}

	@Override
	public @NonNull PublicKeyCredentialCreationOptionsSessionDto generateRegistrationOptionsForExistingAccountAndSaveChallenge(
			@NotBlank String token
	) throws HttpStatusException {
		// Verify the token
		User user = userRestService.validateJwtClaimsForPasskeyAddition(token);
		return generateCreationOptionsForUserAndSaveChallenge(user);
	}

	@Override
	public @NonNull PublicKeyCredentialCreationOptionsSessionDto generateRegistrationOptionsForUserAndSaveChallenge(
			@NonNull String userHandleBase64Url, @NonNull UserVerificationDto userVerificationDto
	) throws HttpStatusException {
		PasskeyUserHandle passkeyUserHandle = passkeyUserHandleRepo.findById(userHandleBase64Url)
				.orElseThrow(() -> new HttpStatusException(HttpStatus.NOT_FOUND, "passkey user handle not found"));

		if (passkeyUserHandle.getUser() == null) {
			throw new HttpStatusException(HttpStatus.NOT_FOUND, "passkey user handle not associated with a user");
		} else {
			long userId = passkeyUserHandle.getUser().getId();
			User user = securityRestService.findUserAndValidateCredentials(userId, userVerificationDto);

			return generateCreationOptionsForUserAndSaveChallenge(user);
		}
	}

	private @NonNull PublicKeyCredentialCreationOptionsSessionDto generateCreationOptionsForUserAndSaveChallenge(
			@NonNull User user
	) {
		long userId = user.getId();
		PasskeyUserHandle passkeyUserHandle = passkeyUserHandleRepo.findByUserId(userId)
				.orElseGet(() -> createPasskeyUserHandleForExistingUser(userId));
		Duration regTimeout = PasskeyUtil.REGISTRATION_TIMEOUT;
		PasskeyChallenge passkeyChallenge = generateChallenge(
				passkeyUserHandle,
				regTimeout.plus(5L, ChronoUnit.SECONDS)
		);
		String userHandleBase64Url = passkeyChallenge.getPasskeyUserHandle().getId();

		byte[] userHandle = Base64UrlUtil.decode(userHandleBase64Url);
		PublicKeyCredentialUserEntity credUser = new PublicKeyCredentialUserEntity(userHandle, user.getEmail(), user.getName());

		// "excludeCredentials" is a list of existing credentials' IDs to prevent duplicating a passkey from the passkey
		// provider. I.e. Prevent users from re-registering existing authenticators
		List<PublicKeyCredentialDescriptor> excludeCredentials = findPreviouslyRegisteredAuthenticators(userHandleBase64Url);

		PublicKeyCredentialRpEntity rp = buildPublicKeyCredentialRpEntity();
		Challenge challenge = new DefaultChallenge(passkeyChallenge.getChallenge());
		return new PublicKeyCredentialCreationOptionsSessionDto(
				passkeyChallenge.getSessionId(),
				PasskeyUtil.generateCreationOptions(rp, credUser, excludeCredentials, challenge, regTimeout)
		);
	}

	@Override
	@Transactional(propagation = TransactionDefinition.Propagation.REQUIRES_NEW)
	public @NonNull PasskeyChallengeAndUserHandle findNonNullChallengeAndDiscard(@NonNull UUID challengeSessionId) throws HttpStatusException {
		PasskeyChallenge passkeyChallenge = passkeyChallengeRepo.findNonExpiredBySessionId(challengeSessionId)
				.orElseThrow(() -> new HttpStatusException(HttpStatus.NOT_FOUND, "invalid or expired challenge session"));

		// Discard the challenge, to prevent replay attacks
		passkeyChallengeRepo.delete(passkeyChallenge);

		return convertToChallengeAndHandle(passkeyChallenge);
	}

	private static PasskeyChallengeAndUserHandle convertToChallengeAndHandle(PasskeyChallenge passkeyChallenge) {
		Challenge challenge = new DefaultChallenge(passkeyChallenge.getChallenge());
		String userHandleBase64Url = passkeyChallenge.getPasskeyUserHandle() == null
				? null
				: passkeyChallenge.getPasskeyUserHandle().getId();
		return new PasskeyChallengeAndUserHandle(challenge, userHandleBase64Url);
	}

	@Override
	public @NonNull RegistrationParameters loadRegistrationParametersForVerification(
			@NonNull RegistrationData registrationData, @NonNull Challenge savedRegistrationChallenge
	) throws HttpStatusException {
		ServerProperty serverProperty = buildServerPropertiesForVerification(savedRegistrationChallenge);
		return PasskeyUtil.loadRegistrationParametersForVerification(serverProperty);
	}

	@Override
	public JsonApiTopLevelResource saveCredential(
			@NonNull String userHandleBase64Url, @NonNull CredentialRecord cred
	) throws HttpStatusException {
		PasskeyUserHandle passkeyUserHandle = passkeyUserHandleRepo.findById(userHandleBase64Url)
				.orElseThrow(() -> new HttpStatusException(HttpStatus.NOT_FOUND, "passkey user handle not found"));

		// If this is for a new user
		if (passkeyUserHandle.getUser() == null) {
			// Create the user, if possible.
			// Throw an exception if "formattedEmail" already exists for a user. We purposely didn't check when generating
			// the PasskeyUserHandle, and it's possible a user with that email could have been created in the meantime.
			User newUser = userRestService.createUser(passkeyUserHandle.getEmail(), passkeyUserHandle.getName(), null);

			// For PasskeyUserHandle, set the foreign key to match the user. We want to retain the "userHandle" value (the
			// ID) for future use. Also, set the email and name to null since they're no longer needed. Otherwise, having
			// values there that may not match the user in the future may cause confusion.
			passkeyUserHandle.setUser(newUser);
			passkeyUserHandle.setEmail(null);
			passkeyUserHandle.setName(null);
			passkeyUserHandle = passkeyUserHandleRepo.update(passkeyUserHandle);
		}

		User user = passkeyUserHandle.getUser();

		PasskeyCredentialsPersistable persistableCreds = PasskeyUtil.convertToPasskeyCredentialsPersistable(cred);

		PasskeyCredentials pc = translateToPasskeyCredentials(persistableCreds, user);
		pc = passkeyCredentialsRepo.save(pc);

		return pc.toTopLevelResource();
	}

	private static PasskeyCredentials translateToPasskeyCredentials(
			PasskeyCredentialsPersistable persistableCreds, User user
	) {
		return PasskeyCredentials.builder()
				.user(user)
				.credentialId(persistableCreds.getBase64UrlCredentialId())
				.attestedCredentialData(persistableCreds.getAttestedCredentialDataBytes())
				.attestationStatementEnvelope(persistableCreds.getAttestationStatementEnvelope())
				.authenticatorExtensions(persistableCreds.getAuthenticatorExtensionsJson())
				.signatureCount(persistableCreds.getSignatureCount())
				.type(persistableCreds.getType())
				.clientExtensions(persistableCreds.getClientExtensionsJson())
				.transports(persistableCreds.getTransports())
				.uvInitialized(persistableCreds.isUvInitialized())
				.backupEligible(persistableCreds.isBackupEligible())
				.backupState(persistableCreds.isBackupState())
				.lastUsedDate(null)
				.passkeyName(null)
				.build();
	}

	private static PasskeyCredentialsPersistable translateToPasskeyCredentialsPersistable(
			PasskeyCredentials pc
	) {
		return PasskeyCredentialsPersistable.builder()
				.base64UrlCredentialId(pc.getCredentialId())
				.attestedCredentialDataBytes(pc.getAttestedCredentialData())
				.attestationStatementEnvelope(pc.getAttestationStatementEnvelope())
				.authenticatorExtensionsJson(pc.getAuthenticatorExtensions())
				.signatureCount(pc.getSignatureCount())
				.type(pc.getType())
				.clientExtensionsJson(pc.getClientExtensions())
				.transports(pc.getTransports())
				.uvInitialized(pc.isUvInitialized())
				.backupEligible(pc.isBackupEligible())
				.backupState(pc.isBackupState())
				.build();
	}

	@Override
	public @NonNull PublicKeyCredentialRequestOptionsSessionDto generateAuthenticationOptionsAndSaveChallenge(
			@Nullable String userHandleBase64Url
	) throws HttpStatusException {

		PublicKeyCredentialRpEntity rp = buildPublicKeyCredentialRpEntity();

		// "allowCredentials" is an array of acceptable credentials for this authentication. If non-empty, it requires
		// users to use a previously registered authenticator. Pass an empty array to let the user select an available
		// passkey from a list shown by the browser.
		List<PublicKeyCredentialDescriptor> allowCredentials = List.of();
		if (userHandleBase64Url != null) {
			// The user is authenticated, so we're likely re-verifying their identity to take a protected action, such
			// as creating an integration token.
			allowCredentials = findPreviouslyRegisteredAuthenticators(userHandleBase64Url);
		}

		// Store the challenge. Even though the timeout in the options is "just a hint" to the browser, that is how long
		// we will honor the challenge. It's a one-time use value, which is also discarded once used.
		// No parameters are provided, so we don't have a "PublicKeyCredentialUserEntity" or "PasskeyUserHandle".
		// That is not a problem because we will look up the user during authentication verification via the credential
		// ID instead of though the PasskeyUserHandle, like we do for registration verification.
		Duration authTimeout = PasskeyUtil.AUTHENTICATION_TIMEOUT;
		PasskeyChallenge passkeyChallenge = generateChallenge(
				null,
				authTimeout.plus(5L, ChronoUnit.SECONDS)
		);
		Challenge challenge = new DefaultChallenge(passkeyChallenge.getChallenge());

		PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions = PasskeyUtil.generateAuthenticationOptions(
				challenge, allowCredentials, authTimeout, rp.getId()
		);

		return new PublicKeyCredentialRequestOptionsSessionDto(
				passkeyChallenge.getSessionId(),
				publicKeyCredentialRequestOptions
		);
	}

	@Override
	public @NonNull AuthenticationParameters loadAuthenticationParametersForVerification(
			@NonNull AuthenticationData authenticationData, @NonNull Challenge savedAuthenticationChallenge
	) {
		// Load the authenticator information persisted during the registration process
		PasskeyCredentials pc = loadPasskeyCredentials(authenticationData.getCredentialId());

		// Validate that the provided user handle matches what we have persisted. This may be overkill, since it is
		// valid to look up a user by credential ID or user handle, and we're effectively requiring both.
		validatePasskeyCredentials(pc, authenticationData.getUserHandle());

		ServerProperty serverProperty = buildServerPropertiesForVerification(savedAuthenticationChallenge);
		Origin origin = findOrigin();
		PasskeyCredentialsPersistable pcp = translateToPasskeyCredentialsPersistable(pc);
		CredentialRecord credentialRecord = PasskeyUtil.translateToCredentialRecord(origin, pcp, savedAuthenticationChallenge);

		String userHandleBase64Url = Base64UrlUtil.encodeToString(authenticationData.getUserHandle());
		List<PublicKeyCredentialDescriptor> allowCredentials = findPreviouslyRegisteredAuthenticators(userHandleBase64Url);

		pc.setLastUsedDate(systemService.getNow());
		pc = passkeyCredentialsRepo.update(pc);

		return PasskeyUtil.buildAuthenticationParameters(serverProperty, credentialRecord, allowCredentials);
	}

	/**
	 * Validate that the provided userHandle matches what we have on record. From the persisted credentials, we're
	 * looking at the associated user, and getting their user handle. That should match the user handle in the provided
	 * data. This may be overkill. According to the Google documentation linked below, we may look up the user by either
	 * the user handle or the credential ID. Using this method means we're effectively requiring both.
	 * @param pc the persisted passkey credentials, loaded from the provided credential ID
	 * @param userHandle the user handle from the provided data
	 * @throws HttpStatusException if the user handle does not match
	 * @see <a href="https://developers.google.com/identity/passkeys/developer-guides/server-authentication#verify_and_sign_in_the_user">Verify and sign in the user</a>
	 */
	private void validatePasskeyCredentials(
			@NonNull PasskeyCredentials pc, @NonNull byte[] userHandle
	) throws HttpStatusException {
		long credentialsUserId = pc.getUser().getId();
		String userHandleFromProvidedData = Base64UrlUtil.encodeToString(userHandle);
		PasskeyUserHandle passkeyUserHandle = passkeyUserHandleRepo.findByUserId(credentialsUserId)
				.orElseThrow(() -> new HttpStatusException(HttpStatus.NOT_FOUND, "passkey user handle not found"));

		if (!passkeyUserHandle.getId().equals(userHandleFromProvidedData)) {
			throw new HttpStatusException(HttpStatus.UNAUTHORIZED, "invalid user handle");
		}
	}

	@Override
	public void updateCounter(byte[] credentialId, long counter) throws HttpStatusException {
		PasskeyCredentials pc = loadPasskeyCredentials(credentialId);
		// The client's authenticator should ideally increment the counter to prevent replay attack.
		// When the client's authenticator is used, the authenticator may increment the counter to identify misbehaving
		// authenticators. The counter on subsequent authentications should only ever increment; if your stored counter
		// is greater than zero, and a subsequent authentication response's counter is the same or lower, then perhaps
		// the authenticator just used to authenticate is in a compromised state.
		// Certain high profile authenticators, like Touch ID on macOS, may always return 0 (zero) for the signature
		// counter. In this case there is nothing an RP can really do to detect a cloned authenticator, especially in
		// the context of multi-device credentials.
		// See https://simplewebauthn.dev/docs/packages/server#3-post-registration-responsibilities
		// See https://stackoverflow.com/questions/78776653/passkey-counter-always-0-macos
		pc.setSignatureCount(counter);
		pc = passkeyCredentialsRepo.update(pc);
	}

	/**
	 * Save the user handle for a new user and the challenge. The email address on PasskeyUserHandle is NOT unique.
	 * We will NOT check if the email already exists until the verification step when we create the user. That way, it's
	 * not so easy to check a large list of email addresses, and whether they already exist.
	 */
	private PasskeyChallenge savePasskeyUserHandleForNewUserWithChallenge(
			PublicKeyCredentialUserEntity credUser, Duration challengeTimeout
	) {
		byte[] userHandle = credUser.getId();
		// For our usage, the "name" from PublicKeyCredentialUserEntity is their email
		String formattedEmail = credUser.getName();
		String formattedDisplayName = credUser.getDisplayName();

		PasskeyUserHandle passkeyUserHandle = PasskeyUserHandle.builder()
				.id(Base64UrlUtil.encodeToString(userHandle))
				.email(formattedEmail)
				.name(formattedDisplayName)
				.build();

		passkeyUserHandle = passkeyUserHandleRepo.save(passkeyUserHandle);

		return generateChallenge(passkeyUserHandle, challengeTimeout);
	}

	/**
	 * Create the user handle for an existing user. Users may not have a user handle, such as if they have never created
	 * a passkey.
	 */
	private @NonNull PasskeyUserHandle createPasskeyUserHandleForExistingUser(long userId) {
		byte[] userHandle = PasskeyUtil.generateUserHandle();

		return passkeyUserHandleRepo.save(PasskeyUserHandle.builder()
				.id(Base64UrlUtil.encodeToString(userHandle))
				.user(User.builder().id(userId).build())
				// Don't set the email or name. We already have a user record, and that is the source of truth.
				.email(null)
				.name(null)
				.build()
		);
	}

	/**
	 * Save the challenge for a short period of time while waiting for verification
	 * @param passkeyUserHandle the passkeyUserHandle, if registering a user. This shall be null for authentication,
	 *            which relies on the credential ID instead.
	 * @param challengeTimeout the duration for which the challenge is valid
	 */
	private PasskeyChallenge generateChallenge(@Nullable PasskeyUserHandle passkeyUserHandle, Duration challengeTimeout) {
		Challenge challenge = new DefaultChallenge();

		PasskeyChallenge passkeyChallenge = PasskeyChallenge.builder()
				.sessionId(UUID.randomUUID())
				.passkeyUserHandle(passkeyUserHandle)
				.challengeExpiration(systemService.getNow().plus(challengeTimeout))
				.challenge(Base64UrlUtil.encodeToString(challenge.getValue()))
				.build();

		return passkeyChallengeRepo.save(passkeyChallenge);
	}

	/**
	 * Retrieve any of the user's previously registered authenticators. This can be used to prevent users from
	 * re-registering existing authenticators via "excludeCredentials", or to require previously registered
	 * authenticators via "allowCredentials".
	 * @see <a href="https://simplewebauthn.dev/docs/packages/server#1-generate-registration-options">Generate registration options</a>
	 * @see <a href="https://www.w3.org/TR/webauthn-1/#dictdef-publickeycredentialdescriptor">Credential Descriptor (dictionary PublicKeyCredentialDescriptor)</a>
	 */
	private @Nullable List<PublicKeyCredentialDescriptor> findPreviouslyRegisteredAuthenticators(
			@NonNull String userHandleBase64Url
	) throws HttpStatusException {

		List<PasskeyCredentials> passkeyCredentials = passkeyCredentialsRepo.findByUserHandle(userHandleBase64Url);
		return passkeyCredentials.stream()
				.map(pc -> new PublicKeyCredentialDescriptor(
						PublicKeyCredentialType.PUBLIC_KEY,
						Base64UrlUtil.decode(pc.getCredentialId()),
						PasskeyUtil.mapTransportStrings(pc.getTransports())
				))
				.toList();
	}

	private @NonNull PasskeyCredentials loadPasskeyCredentials(byte[] credentialId) throws HttpStatusException {
		if (credentialId == null) {
			throw new HttpStatusException(HttpStatus.BAD_REQUEST, "credential ID not provided");
		}
		String base64UrlCredentialId = Base64UrlUtil.encodeToString(credentialId);

		return passkeyCredentialsRepo.findByCredentialId(base64UrlCredentialId)
				.orElseThrow(() -> new HttpStatusException(HttpStatus.NOT_FOUND, "credentials not found"));
	}

	@Override
	public @NonNull String findUserHandleBase64Url(
			@NonNull String userIdStr, boolean generateIfNotFound
	) throws HttpStatusException {
		long userId = Long.parseLong(userIdStr);
		String userHandleBase64Url = passkeyUserHandleRepo.findByUserId(userId)
				.map(PasskeyUserHandle::getId)
				.orElseGet(() -> !generateIfNotFound
						? null
						: createPasskeyUserHandleForExistingUser(userId).getId()
				);

		if (userHandleBase64Url == null) {
			// User is likely trying to re-verify their account via passkeys to take a protected action, but we've
			// never created a passkey user handle for this user. And that means the user has never had a passkey.
			throw new HttpStatusException(HttpStatus.NOT_FOUND, "user has never created a passkey");
		} else {
			return userHandleBase64Url;
		}
	}

	@Override
	public @Nullable AuthenticationUserInfo generateAuthenticationUserInfo(byte[] credentialId) {
		String base64UrlCredentialId = Base64UrlUtil.encodeToString(credentialId);

		User user = passkeyCredentialsRepo.findByCredentialId(base64UrlCredentialId)
				.flatMap(pc -> userRepo.findById(pc.getUser().getId()))
				.orElse(null);

		if (user == null) {
			return null;
		} else {
			// Even though we did not use an access token authorization to get here, we want to provide future
			// authorization via an access token
			Map<String, Object> jwtClaims = TokenUtil.buildJwtClaims(user);

			return new AuthenticationUserInfo(
					String.valueOf(user.getId()),
					user.isEnabled(),
					null,
					jwtClaims
			);
		}
	}

	@Override
	public void deleteExpiredChallengesAndPasskeyUserHandles() {
		// Delete any expired challenges
		passkeyChallengeRepo.deleteWhereExpired();

		// Delete all passkey user handle records that have neither a user ID nor a challenge.
		passkeyUserHandleRepo.deleteWhereUserIdIsNullAndHasNoChallenge();
	}
}
