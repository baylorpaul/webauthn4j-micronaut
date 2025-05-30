package io.github.baylorpaul.webauthn4jmicronaut.rest;

import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.TokenBinding;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.*;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.PublicKeyCredentialCreationOptionsSessionDto;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.PublicKeyCredentialRequestOptionsSessionDto;
import io.github.baylorpaul.webauthn4jmicronaut.entity.PasskeyChallenge;
import io.github.baylorpaul.webauthn4jmicronaut.entity.PasskeyCredentials;
import io.github.baylorpaul.webauthn4jmicronaut.entity.PasskeyUserHandle;
import io.github.baylorpaul.webauthn4jmicronaut.entity.User;
import io.github.baylorpaul.webauthn4jmicronaut.repo.PasskeyChallengeRepository;
import io.github.baylorpaul.webauthn4jmicronaut.repo.PasskeyCredentialsRepository;
import io.github.baylorpaul.webauthn4jmicronaut.repo.PasskeyUserHandleRepository;
import io.github.baylorpaul.webauthn4jmicronaut.security.PasskeyConfigurationProperties;
import io.github.baylorpaul.webauthn4jmicronaut.security.PasskeyService;
import io.github.baylorpaul.webauthn4jmicronaut.security.model.AttestationStatementEnvelope;
import io.github.baylorpaul.webauthn4jmicronaut.security.model.PasskeyChallengeAndUserHandle;
import io.github.baylorpaul.webauthn4jmicronaut.service.SystemService;
import io.github.baylorpaul.webauthn4jmicronaut.util.ApiUtil;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.exceptions.HttpStatusException;
import io.micronaut.transaction.TransactionDefinition;
import io.micronaut.transaction.annotation.Transactional;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.validation.constraints.NotBlank;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Singleton
@Transactional
public class PasskeyUserRestService implements PasskeyService {

	/**
	 * The timeout between retrieving registration options and verification. This indicates the time the calling web app
	 * is willing to wait for the creation operation to complete, as well as the duration that the server will honor the
	 * challenge. A challenge should only be valid for 30 seconds to a few minutes to prevent replay attacks. A long
	 * timeout could allow an attacker more time to potentially intercept the registration process. A shorter timeout,
	 * on the other hand, could frustrate legitimate users who might experience temporary network issues or device
	 * glitches. 60 seconds is a common industry value.
	 */
	private static final Duration REGISTRATION_TIMEOUT = Duration.ofSeconds(60);
	/**
	 * The timeout between retrieving authentication options and verification. This is a hint for the web app, as well
	 * as the duration that the server will honor the challenge. It should be reasonably generous, and shorter than the
	 * lifetime of the challenge.
	 * @see <a href="https://developers.google.com/identity/passkeys/developer-guides/server-authentication#create_credential_request_options">Create credential request options</a>
	 * @see <a href="https://w3c.github.io/webauthn/#sctn-timeout-recommended-range">Recommended Range for Ceremony Timeouts</a>
	 */
	private static final Duration AUTHENTICATION_TIMEOUT = Duration.ofMinutes(5);

	/**
	 * It is recommended that relying parties that wish to support a wide range of authenticators should include at
	 * least the following values in the provided choices: Ed25519, ES256, RS256
	 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions#alg">PublicKeyCredentialCreationOptions.alg</a>
	 * @see <a href="https://www.corbado.com/blog/webauthn-pubkeycredparams-credentialpublickey#6-recommendation">Select the right encryption algorithms</a>
	 */
	private static final List<PublicKeyCredentialParameters> PUB_KEY_CRED_PARAMS = List.of(
			new PublicKeyCredentialParameters(
					PublicKeyCredentialType.PUBLIC_KEY,
					COSEAlgorithmIdentifier.EdDSA
			),
			new PublicKeyCredentialParameters(
					PublicKeyCredentialType.PUBLIC_KEY,
					COSEAlgorithmIdentifier.ES256
			),
			new PublicKeyCredentialParameters(
					PublicKeyCredentialType.PUBLIC_KEY,
					COSEAlgorithmIdentifier.RS256
			)
	);

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
		Origin origin = findOrigin();
		String rpId = passkeyProps.getRpId();
		// tokenBinding is deprecated as of Level 3 of the spec, but the field is reserved so that it won't be reused
		// for a different purpose. See https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorResponse/clientDataJSON#tokenbinding
		byte[] tokenBindingId = null;
		return new ServerProperty(origin, rpId, previouslyIssuedChallenge, tokenBindingId);
	}

	private static ObjectConverter findObjectConverter() {
// TODO move this to a bean, and use it in PasskeyController for WebAuthnManager.createNonStrictWebAuthnManager() as well
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

		byte[] userHandle = generateUserHandle();

		// The PublicKeyCredentialUserEntity will be converted into a User once the registration is verified.
		// The "name" should be unique, and can be a username, email address, etc.
		// In our case, we're using an email address for "name".
		return new PublicKeyCredentialUserEntity(userHandle, formattedEmail, formattedDisplayName);
	}

	private static byte[] generateUserHandle() {
		// This is the user handle of the user account entity. To ensure secure operation, authentication and
		// authorization decisions MUST be made on the basis of this id member, not the displayName nor name members.
		// It is RECOMMENDED to let the user handle be 64 random bytes, and store this value in the user's account.
		// It should not contain PII (Personally Identifiable Information).
		// Don't use this as the user's primary key. Primary keys tend to become de facto PII in systems, because
		// they're extensively used.
		SecureRandom random = new SecureRandom();
		byte[] userHandle = new byte[64];
		random.nextBytes(userHandle);

		return userHandle;
	}

	@Override
	public @NonNull PublicKeyCredentialCreationOptionsSessionDto generateRegistrationOptionsAndSaveChallenge(
			@NotBlank String uniqueNameOrEmail, @Nullable String displayName
	) throws HttpStatusException {
// TODO If adding a passkey to an existing user, require authentication, and look up the pre-existing user record
		PublicKeyCredentialUserEntity credUser = buildCredentialUserIfNotExists(uniqueNameOrEmail, displayName);

		// "excludeCredentials" is a list of existing credentials' IDs to prevent duplicating a passkey from the passkey
		// provider. I.e. Prevent users from re-registering existing authenticators
// TODO when does "excludeCredentials" get used? Just when adding a passkey to an existing user? At the time of this
//  writing the "userHandle" was always just generated, so there will never be any associated
//  PublicKeyCredentialDescriptor records to "exclude".
		List<PublicKeyCredentialDescriptor> excludeCredentials = findPreviouslyRegisteredAuthenticators(credUser);

		// When generating passkey registration options, we'll have the email and display name, but not during
		// registration verification. The WebAuthn standard does not include this information in the credential data.
		// We'll only have the credential ID. So we'll need to persist this information now, and look it up when
		// registration is verified.

		// Store the challenge, associated with the user handle. Even though the timeout in the options is "just a hint"
		// to the browser, that is how long we will honor the challenge. It's a one-time use value, which is also discarded once used.
		PasskeyChallenge passkeyChallenge = savePasskeyUserHandleForNewUserWithChallenge(
				credUser,
				REGISTRATION_TIMEOUT.plus(5L, ChronoUnit.SECONDS)
		);

		return generateCreationOptionsAndSaveChallenge(credUser, excludeCredentials, passkeyChallenge);
	}

	private @NonNull PublicKeyCredentialCreationOptionsSessionDto generateCreationOptionsAndSaveChallenge(
			@NonNull PublicKeyCredentialUserEntity credUser,
			@Nullable List<PublicKeyCredentialDescriptor> excludeCredentials,
			PasskeyChallenge passkeyChallenge
	) {
		PublicKeyCredentialRpEntity rp = buildPublicKeyCredentialRpEntity();

		AuthenticatorSelectionCriteria authenticatorSelection = new AuthenticatorSelectionCriteria(
				AuthenticatorAttachment.PLATFORM,
				ResidentKeyRequirement.PREFERRED,
				UserVerificationRequirement.PREFERRED
		);

		// An array of strings providing hints as to what authentication UI the user-agent should provide for the user.
		List<PublicKeyCredentialHints> hints = List.of();

		// Don't prompt users for additional information about the authenticator (smoother UX).
		// In general, relying parties aren't encouraged to request attestation.
		// When registering an authenticator for a new account, typically a Trust On First Use (TOFU) model applies; and
		// when adding an authenticator to an existing account, a user has already been authenticated and has
		// established a secure session.
		// See https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Attestation_and_Assertion#attestation
		AttestationConveyancePreference attestation = AttestationConveyancePreference.NONE;

		AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensions = new AuthenticationExtensionsClientInputs.BuilderForRegistration()
				.setCredProps(true)
				// Optionally enable "User Verification Method". See https://webauthn4j.github.io/webauthn4j-spring-security/en/#attestation-options-endpoint-assertion-options-endpoint
				//.setUvm(true)
				.build();

		Challenge challenge = new DefaultChallenge(passkeyChallenge.getChallenge());

		PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions = new PublicKeyCredentialCreationOptions(
				rp,
				credUser,
				challenge,
				PUB_KEY_CRED_PARAMS,
				REGISTRATION_TIMEOUT.toMillis(),
				excludeCredentials,
				authenticatorSelection,
				hints,
				attestation,
				extensions
		);

		return new PublicKeyCredentialCreationOptionsSessionDto(
				passkeyChallenge.getSessionId(),
				publicKeyCredentialCreationOptions
		);
	}

	@Override
	@Transactional(propagation = TransactionDefinition.Propagation.REQUIRES_NEW)
	public @NonNull PasskeyChallengeAndUserHandle findNonNullChallengeAndDiscard(@NonNull UUID challengeSessionId) throws HttpStatusException {
		PasskeyChallenge passkeyChallenge = passkeyChallengeRepo.findNonExpiredBySessionId(challengeSessionId)
				.orElseThrow(() -> new HttpStatusException(HttpStatus.NOT_FOUND, "invalid or expired challenge session"));

		// Discard the challenge, to prevent replay attacks
		passkeyChallengeRepo.delete(passkeyChallenge);

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
// TODO maybe remove the "registrationData" parameter
/* TODO none of this is probably needed
		AttestationObject attestationObject = registrationData.getAttestationObject();
		if (attestationObject == null) {
			throw new HttpStatusException(HttpStatus.UNAUTHORIZED, "attestation object not found");
		}
		AttestedCredentialData attestedCredentialData = attestationObject.getAuthenticatorData().getAttestedCredentialData();
		if (attestedCredentialData == null) {
			throw new HttpStatusException(HttpStatus.UNAUTHORIZED, "attested credential data not found");
		}
		byte[] credentialId = attestedCredentialData.getCredentialId();
*/

		ServerProperty serverProperty = buildServerPropertiesForVerification(savedRegistrationChallenge);

		// A parameter indicating whether user verification, such as biometrics or PIN confirmation on the
		// authenticator, is required.
		boolean userVerificationRequired = false;

		// This verifies the UP flag, which indicates that the user performed some gesture input. This gesture could be
		// something like a touch on a capacitive button, not limited to biometric authentication. In WebAuthn, the UP
		// flag is generally required, so it should be set to true, except in scenarios that auto-generating credentials
		// during a password-to-passkey upgrade, where false is required.
		// See https://webauthn4j.github.io/webauthn4j/en/#registering-the-webauthn-public-key-credential-on-the-server
		boolean userPresenceRequired = true;

		return new RegistrationParameters(
				serverProperty, PUB_KEY_CRED_PARAMS, userVerificationRequired, userPresenceRequired
		);
	}

	@Override
	public void saveCredential(
			@NonNull String userHandleBase64Url, @NonNull CredentialRecord cred
	) throws HttpStatusException {
		AttestedCredentialData attestedCredentialData = cred.getAttestedCredentialData();
		String base64UrlCredentialId = Base64UrlUtil.encodeToString(attestedCredentialData.getCredentialId());

		// Convert the attested credential data to a byte array according to https://www.w3.org/TR/webauthn-1/#sec-attested-credential-data
		// The public key in this data is "public", and does not need to be encrypted, despite the suggestion in this
		// article: https://www.corbado.com/blog/passkey-webauthn-database-guide#security-considerations
		// See https://webauthn.guide/#about-webauthn - this explains that "The public key is not secret, because it is
		// effectively useless without the corresponding private key. The fact that the server receives no secret has
		// far-reaching implications for the security of users and organizations. Databases are no longer as attractive
		// to hackers, because the public keys aren't useful to them."
		// Hackers would do not have the private key, which is on the user's device and is the crucial part for
		// authentication.
		AttestedCredentialDataConverter attestedCredentialDataConverter = findAttestedCredentialDataConverter();
		byte[] attestedCredentialDataBytes = attestedCredentialDataConverter.convert(attestedCredentialData);

		PasskeyUserHandle passkeyUserHandle = passkeyUserHandleRepo.findById(userHandleBase64Url)
				.orElseThrow(() -> new HttpStatusException(HttpStatus.NOT_FOUND, "passkey user handle not found"));

		// Create the user, if possible.
		// Throw an exception if "formattedEmail" already exists for a user. We purposely didn't check when generating
		// the PasskeyUserHandle, and it's possible a user with that email could have been created in the meantime.
		User user = userRestService.createUser(passkeyUserHandle.getEmail(), passkeyUserHandle.getName(), null);

		// For PasskeyUserHandle, set the foreign key to match the user. We want to retain the "userHandle" value (the
		// ID) for future use. Also, set the email and name to null since they're no longer needed. Otherwise, having
		// values there that may not match the user in the future may cause confusion.
		passkeyUserHandle.setUser(user);
		passkeyUserHandle.setEmail(null);
		passkeyUserHandle.setName(null);
		passkeyUserHandle = passkeyUserHandleRepo.update(passkeyUserHandle);

		AttestationStatement attestationStatement = cred.getAttestationStatement();
		if (attestationStatement == null) {
			throw new HttpStatusException(HttpStatus.UNAUTHORIZED, "missing attestation statement");
		}
		byte[] attestationStatementEnvelope = serializeAttestationStatementEnvelope(attestationStatement);

		CollectedClientData clientData = cred.getClientData();
		String clientDataTypeStr = clientData == null ? null : clientData.getType().getValue();
		if (clientDataTypeStr == null) {
			throw new HttpStatusException(HttpStatus.UNAUTHORIZED, "missing client data type");
		}

		List<String> transportStrs = mapTransportSet(cred.getTransports());

		Boolean uvInitialized = cred.isUvInitialized();
		Boolean backupEligible = cred.isBackupEligible();
		Boolean backedUp = cred.isBackedUp();

		PasskeyCredentials pc = PasskeyCredentials.builder()
				.user(user)
				.credentialId(base64UrlCredentialId)
				//.aaguid(attestedCredentialData.getAaguid().getValue())
				//.coseKey(attestedCredentialData.getCOSEKey())
				.attestedCredentialData(attestedCredentialDataBytes)
				.attestationStatementEnvelope(attestationStatementEnvelope)
				//.attestationStatement(attestationStatement)
				//.authenticatorExtensions(authenticatorExtensions)
				.signatureCount(0L)
				.lastUsedDate(null)
				.type(clientDataTypeStr)
				//.clientExtensions(cred.getClientExtensions())
				.transports(transportStrs)
				.uvInitialized(uvInitialized != null && uvInitialized.booleanValue())
				.backupEligible(backupEligible != null && backupEligible.booleanValue())
				.backupState(backedUp != null && backedUp.booleanValue())
				.build();

		pc = passkeyCredentialsRepo.save(pc);
	}

	@Override
	public @NonNull PublicKeyCredentialRequestOptionsSessionDto generateAuthenticationOptionsAndSaveChallenge() throws HttpStatusException {

		// We can't find a user because we want the browser to be able to invoke this API method without providing any
		// information so that it can autofill the input.
		//PublicKeyCredentialUserEntity credUser = null;

		PublicKeyCredentialRpEntity rp = buildPublicKeyCredentialRpEntity();

		// "allowCredentials" is an array of acceptable credentials for this authentication. If non-empty, it requires
		// users to use a previously-registered authenticator. Pass an empty array to let the user select an available
		// passkey from a list shown by the browser.
// TODO when authenticating while already logged in, we may want to provide values for this list. E.g. if authenticating in order to create an integration token
		List<PublicKeyCredentialDescriptor> allowCredentials = List.of();
		//if (credUser != null) {
		//	allowCredentials = passkeyService.findPreviouslyRegisteredAuthenticators(credUser);
		//}

		List<PublicKeyCredentialHints> hints = null;
		AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> extensions = null;

		// Store the challenge. Even though the timeout in the options is "just a hint" to the browser, that is how long
		// we will honor the challenge. It's a one-time use value, which is also discarded once used.
		// No parameters are provided, so we don't have a "PublicKeyCredentialUserEntity" or "PasskeyUserHandle".
		// That is not a problem because we will look up the user during authentication verification via the credential
		// ID instead of though the PasskeyUserHandle, like we do for registration verification.
		PasskeyChallenge passkeyChallenge = generateChallenge(null, AUTHENTICATION_TIMEOUT.plus(5L, ChronoUnit.SECONDS));
		Challenge challenge = new DefaultChallenge(passkeyChallenge.getChallenge());

		PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions = new PublicKeyCredentialRequestOptions(
				challenge,
				AUTHENTICATION_TIMEOUT.toMillis(),
				rp.getId(),
				allowCredentials,
				UserVerificationRequirement.PREFERRED,
				hints,
				extensions
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
		CredentialRecord credentialRecord = translateToCredentialRecord(pc, savedAuthenticationChallenge);

		// expectations
// TODO set "allowCredentials". When authenticating while already logged in, we may want to provide values for this
//  list. E.g. if authenticating in order to create an integration token
		List<byte[]> allowCredentials = null;
		boolean userVerificationRequired = true;
		boolean userPresenceRequired = true;

		pc.setLastUsedDate(systemService.getNow());
		pc = passkeyCredentialsRepo.update(pc);

		return new AuthenticationParameters(
				serverProperty,
				credentialRecord,
				allowCredentials,
				userVerificationRequired,
				userPresenceRequired
		);
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
	 * Serialize the attestation type and attestation statement in an "envelope", encoded in CBOR (Concise Binary Object
	 * Representation).
	 * @see <a href="https://webauthn4j.github.io/webauthn4j/en/#attestationstatement">attestationStatement</a>
	 * @see <a href="https://www.w3.org/TR/webauthn-1/#sctn-attestation">Attestation</a>
	 * @see <a href="https://www.w3.org/TR/webauthn-1/#sctn-attestation-types">Attestation Types</a>
	 */
	private @NonNull byte[] serializeAttestationStatementEnvelope(@NonNull AttestationStatement attestationStatement) {
		ObjectConverter objectConverter = findObjectConverter();
		AttestationStatementEnvelope envelope = new AttestationStatementEnvelope(attestationStatement);
		return objectConverter.getCborConverter().writeValueAsBytes(envelope);
	}

	/**
	 * Deserialize the attestation type and attestation statement from an "envelope", encoded in CBOR (Concise Binary
	 * Object Representation).
	 * @throws HttpStatusException if the attestation statement could not be deserialized
	 * @see <a href="https://webauthn4j.github.io/webauthn4j/en/#attestationstatement">attestationStatement</a>
	 * @see <a href="https://www.w3.org/TR/webauthn-1/#sctn-attestation">Attestation</a>
	 * @see <a href="https://www.w3.org/TR/webauthn-1/#sctn-attestation-types">Attestation Types</a>
	 */
	private @NonNull AttestationStatement deserializeAttestationStatementEnvelope(
			@NonNull byte[] serializedEnvelope
	) throws HttpStatusException {
		ObjectConverter objectConverter = findObjectConverter();
		AttestationStatementEnvelope envelope = objectConverter.getCborConverter().readValue(serializedEnvelope, AttestationStatementEnvelope.class);
		if (envelope == null || envelope.getAttestationStatement() == null) {
			throw new HttpStatusException(HttpStatus.UNAUTHORIZED, "invalid attestation statement envelope");
		}
		return envelope.getAttestationStatement();
	}

	/**
	 * Retrieve any of the user's previously registered authenticators. This can be used to prevent users from
	 * re-registering existing authenticators via "excludeCredentials", or to require previously registered
	 * authenticators via "allowCredentials".
	 * @see <a href="https://simplewebauthn.dev/docs/packages/server#1-generate-registration-options">Generate registration options</a>
	 * @see <a href="https://www.w3.org/TR/webauthn-1/#dictdef-publickeycredentialdescriptor">Credential Descriptor (dictionary PublicKeyCredentialDescriptor)</a>
	 */
	private @Nullable List<PublicKeyCredentialDescriptor> findPreviouslyRegisteredAuthenticators(
			@NonNull PublicKeyCredentialUserEntity credUser
	) throws HttpStatusException {
		String userHandleBase64Url = Base64UrlUtil.encodeToString(credUser.getId());

		List<PasskeyCredentials> passkeyCredentials = passkeyCredentialsRepo.findByUserHandle(userHandleBase64Url);
		return passkeyCredentials.stream()
				.map(pc -> new PublicKeyCredentialDescriptor(
						PublicKeyCredentialType.PUBLIC_KEY,
						Base64UrlUtil.decode(pc.getCredentialId()),
						mapTransportStrings(pc.getTransports())
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

	/**
	 * @throws HttpStatusException if the credentials could not be translated
	 */
	private CredentialRecord translateToCredentialRecord(PasskeyCredentials pc, Challenge savedAuthenticationChallenge) throws HttpStatusException {
		byte[] attestedCredentialId = Base64UrlUtil.decode(pc.getCredentialId());

		byte[] attestationStatementEnvelope = pc.getAttestationStatementEnvelope();
		AttestationStatement attestationStatement = deserializeAttestationStatementEnvelope(attestationStatementEnvelope);

		// Decode the attested credential data byte array according to https://www.w3.org/TR/webauthn-1/#sec-attested-credential-data
		AttestedCredentialDataConverter attestedCredentialDataConverter = findAttestedCredentialDataConverter();
		byte[] attestedCredentialDataBytes = pc.getAttestedCredentialData();
		AttestedCredentialData attestedCredentialData = attestedCredentialDataConverter.convert(attestedCredentialDataBytes);

		if (!Arrays.equals(attestedCredentialId, attestedCredentialData.getCredentialId())) {
			// The stored credential ID in the attested credential data does not match the database's credential ID.
			// This is unexpected, and indicates the database has been tampered with.
			throw new HttpStatusException(HttpStatus.UNAUTHORIZED, "invalid credential ID");
		}

// TODO should this have any other value?
		//AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> authenticatorExtensions = pc.getAuthenticatorExtensions();
		AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> authenticatorExtensions = new AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration()
				.build();

		CollectedClientData clientData = buildCollectedClientData(pc.getType(), savedAuthenticationChallenge);

// TODO persist this and read it here: String serializedClientExtensions = objectConverter.getJsonConverter().writeValueAsString(clientExtensions);
//  See https://webauthn4j.github.io/webauthn4j/en/#clientextensions
		//AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions = pc.getClientExtensions();
		AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions = new AuthenticationExtensionsClientOutputs.BuilderForRegistration()
				.build();

		Set<AuthenticatorTransport> transports = mapTransportStrings(pc.getTransports());

		return new CredentialRecordImpl(
				attestationStatement,
				pc.isUvInitialized(),
				pc.isBackupEligible(),
				pc.isBackupState(),
				pc.getSignatureCount(),
				attestedCredentialData,
				authenticatorExtensions,
				clientData,
				clientExtensions,
				transports
		);
	}

	private CollectedClientData buildCollectedClientData(String clientDataTypeStr, Challenge challenge) {
		ClientDataType clientDataType = ClientDataType.create(clientDataTypeStr);

		Origin origin = findOrigin();
		Boolean crossOrigin = null;
		TokenBinding tokenBinding = null;
		return new CollectedClientData(
				clientDataType,
				challenge,
				origin,
				crossOrigin,
				tokenBinding
		);
	}

	private static List<String> mapTransportSet(Set<AuthenticatorTransport> transports) {
		return transports == null ? null : transports.stream().map(AuthenticatorTransport::getValue).toList();
	}

	private static Set<AuthenticatorTransport> mapTransportStrings(List<String> transportStrs) {
		return transportStrs == null
				? null
				: transportStrs.stream().map(AuthenticatorTransport::create).collect(Collectors.toSet());
	}

	@Override
	public void deleteExpiredChallengesAndPasskeyUserHandles() {
		// Delete any expired challenges
		passkeyChallengeRepo.deleteWhereExpired();

		// Delete all passkey user handle records that have neither a user ID nor a challenge.
		passkeyUserHandleRepo.deleteWhereUserIdIsNullAndHasNoChallenge();
	}
}
