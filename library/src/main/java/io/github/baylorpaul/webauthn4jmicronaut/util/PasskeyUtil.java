package io.github.baylorpaul.webauthn4jmicronaut.util;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.JsonConverter;
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
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.*;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import io.github.baylorpaul.webauthn4jmicronaut.security.model.AttestationStatementEnvelope;
import io.github.baylorpaul.webauthn4jmicronaut.security.model.PasskeyCredentialsPersistable;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.exceptions.HttpStatusException;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class PasskeyUtil {

	/**
	 * The timeout between retrieving registration options and verification. This indicates the time the calling web app
	 * is willing to wait for the creation operation to complete, as well as the duration that the server will honor the
	 * challenge. A challenge should only be valid for 30 seconds to a few minutes to prevent replay attacks. A long
	 * timeout could allow an attacker more time to potentially intercept the registration process. A shorter timeout,
	 * on the other hand, could frustrate legitimate users who might experience temporary network issues or device
	 * glitches. 60 seconds is a common industry value.
	 */
	public static final Duration REGISTRATION_TIMEOUT = Duration.ofSeconds(60);

	/**
	 * The timeout between retrieving authentication options and verification. This is a hint for the web app, as well
	 * as the duration that the server will honor the challenge. It should be reasonably generous, and shorter than the
	 * lifetime of the challenge.
	 * @see <a href="https://developers.google.com/identity/passkeys/developer-guides/server-authentication#create_credential_request_options">Create credential request options</a>
	 * @see <a href="https://w3c.github.io/webauthn/#sctn-timeout-recommended-range">Recommended Range for Ceremony Timeouts</a>
	 */
	public static final Duration AUTHENTICATION_TIMEOUT = Duration.ofMinutes(5);

	private static ObjectConverter findObjectConverter() {
		return new ObjectConverter();
	}

	private static JsonConverter findJsonConverter() {
		return findObjectConverter().getJsonConverter();
	}

	private static CborConverter findCborConverter() {
		return findObjectConverter().getCborConverter();
	}

	/**
	 * Create a WebAuthnManager. Since most sites don’t require strict attestation statement verification, WebAuthn4J
	 * provides WebAuthnManager.createNonStrictWebAuthnManager factory method that returns an WebAuthnManager instance
	 * configured AttestationStatementVerifier and CertPathTrustworthinessVerifier not to verify attestation statements.
	 * @see <a href="https://webauthn4j.github.io/webauthn4j/en/#configuration">WebAuthn4J Configuration</a>
	 */
	public static WebAuthnManager createWebAuthnManager() {
		ObjectConverter objectConverter = findObjectConverter();
		return WebAuthnManager.createNonStrictWebAuthnManager(objectConverter);
	}

	private static AttestedCredentialDataConverter findAttestedCredentialDataConverter() {
		ObjectConverter objectConverter = findObjectConverter();
		return new AttestedCredentialDataConverter(objectConverter);
	}

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

	/**
	 * Generate a new and random passkey user handle.
	 * This is the user handle of the user account entity. To ensure secure operation, authentication and authorization
	 * decisions MUST be made on the basis of this id member, not the displayName nor name members.
	 * It is RECOMMENDED to let the user handle be 64 random bytes, and store this value in the user's account.
	 * It should not contain PII (Personally Identifiable Information).
	 * Don't use this as the user's primary key. Primary keys tend to become de facto PII in systems, because they're
	 * extensively used.
	 */
	public static byte[] generateUserHandle() {
		SecureRandom random = new SecureRandom();
		byte[] userHandle = new byte[64];
		random.nextBytes(userHandle);

		return userHandle;
	}

	public static @NonNull PublicKeyCredentialCreationOptions generateCreationOptions(
			@NonNull PublicKeyCredentialRpEntity rp,
			@NonNull PublicKeyCredentialUserEntity credUser,
			@Nullable List<PublicKeyCredentialDescriptor> excludeCredentials,
			@NonNull Challenge challenge,
			@NonNull Duration timeout
	) {
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

		return new PublicKeyCredentialCreationOptions(
				rp,
				credUser,
				challenge,
				PUB_KEY_CRED_PARAMS,
				timeout.toMillis(),
				excludeCredentials,
				authenticatorSelection,
				hints,
				attestation,
				extensions
		);
	}

	public static RegistrationParameters loadRegistrationParametersForVerification(
			@NonNull ServerProperty serverProperty
	) {
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

	public static PasskeyCredentialsPersistable convertToPasskeyCredentialsPersistable(
			@NonNull CredentialRecord cred
	) {
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

		JsonConverter jsonConverter = findJsonConverter();
		// See https://webauthn4j.github.io/webauthn4j/en/#clientextensions
		String serializedAuthenticatorExtensions = jsonConverter.writeValueAsString(cred.getAuthenticatorExtensions());
		String serializedClientExtensions = jsonConverter.writeValueAsString(cred.getClientExtensions());

		List<String> transportStrs = mapTransportSet(cred.getTransports());

		Boolean uvInitialized = cred.isUvInitialized();
		Boolean backupEligible = cred.isBackupEligible();
		Boolean backedUp = cred.isBackedUp();

		return PasskeyCredentialsPersistable.builder()
				.base64UrlCredentialId(base64UrlCredentialId)
				.attestedCredentialDataBytes(attestedCredentialDataBytes)
				.attestationStatementEnvelope(attestationStatementEnvelope)
				.authenticatorExtensionsJson(serializedAuthenticatorExtensions)
				.signatureCount(0L)
				.type(clientDataTypeStr)
				.clientExtensionsJson(serializedClientExtensions)
				.transports(transportStrs)
				.uvInitialized(uvInitialized != null && uvInitialized.booleanValue())
				.backupEligible(backupEligible != null && backupEligible.booleanValue())
				.backupState(backedUp != null && backedUp.booleanValue())
				.build();
	}

	/**
	 * Serialize the attestation type and attestation statement in an "envelope", encoded in CBOR (Concise Binary Object
	 * Representation).
	 * @see <a href="https://webauthn4j.github.io/webauthn4j/en/#attestationstatement">attestationStatement</a>
	 * @see <a href="https://www.w3.org/TR/webauthn-1/#sctn-attestation">Attestation</a>
	 * @see <a href="https://www.w3.org/TR/webauthn-1/#sctn-attestation-types">Attestation Types</a>
	 */
	private static @NonNull byte[] serializeAttestationStatementEnvelope(@NonNull AttestationStatement attestationStatement) {
		CborConverter cborConverter = findCborConverter();
		AttestationStatementEnvelope envelope = new AttestationStatementEnvelope(attestationStatement);
		return cborConverter.writeValueAsBytes(envelope);
	}

	/**
	 * Deserialize the attestation type and attestation statement from an "envelope", encoded in CBOR (Concise Binary
	 * Object Representation).
	 * @throws HttpStatusException if the attestation statement could not be deserialized
	 * @see <a href="https://webauthn4j.github.io/webauthn4j/en/#attestationstatement">attestationStatement</a>
	 * @see <a href="https://www.w3.org/TR/webauthn-1/#sctn-attestation">Attestation</a>
	 * @see <a href="https://www.w3.org/TR/webauthn-1/#sctn-attestation-types">Attestation Types</a>
	 */
	private static @NonNull AttestationStatement deserializeAttestationStatementEnvelope(
			@NonNull byte[] serializedEnvelope
	) throws HttpStatusException {
		CborConverter cborConverter = findCborConverter();
		AttestationStatementEnvelope envelope = cborConverter.readValue(serializedEnvelope, AttestationStatementEnvelope.class);
		if (envelope == null || envelope.getAttestationStatement() == null) {
			throw new HttpStatusException(HttpStatus.UNAUTHORIZED, "invalid attestation statement envelope");
		}
		return envelope.getAttestationStatement();
	}

	public static @NonNull PublicKeyCredentialRequestOptions generateAuthenticationOptions(
			@NonNull Challenge challenge, List<PublicKeyCredentialDescriptor> allowCredentials,
			@NonNull Duration timeout, @NonNull String rpId
	) {
		List<PublicKeyCredentialHints> hints = null;
		AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> extensions = null;

		return new PublicKeyCredentialRequestOptions(
				challenge,
				timeout.toMillis(),
				rpId,
				allowCredentials,
				UserVerificationRequirement.PREFERRED,
				hints,
				extensions
		);
	}

	public static AuthenticationParameters buildAuthenticationParameters(
			ServerProperty serverProperty, CredentialRecord credentialRecord,
			List<PublicKeyCredentialDescriptor> allowCredentials
	) {
		// expectations
		List<byte[]> allowCredentialIds = allowCredentials == null
				? null
				: allowCredentials.stream().map(PublicKeyCredentialDescriptor::getId).toList();
		boolean userVerificationRequired = true;
		boolean userPresenceRequired = true;

		return new AuthenticationParameters(
				serverProperty,
				credentialRecord,
				allowCredentialIds,
				userVerificationRequired,
				userPresenceRequired
		);
	}

	/**
	 * @throws HttpStatusException if the credentials could not be translated
	 */
	public static CredentialRecord translateToCredentialRecord(
			Origin origin, PasskeyCredentialsPersistable pcp, Challenge savedAuthenticationChallenge
	) throws HttpStatusException {
		byte[] attestedCredentialId = Base64UrlUtil.decode(pcp.getBase64UrlCredentialId());

		byte[] attestationStatementEnvelope = pcp.getAttestationStatementEnvelope();
		AttestationStatement attestationStatement = deserializeAttestationStatementEnvelope(attestationStatementEnvelope);

		// Decode the attested credential data byte array according to https://www.w3.org/TR/webauthn-1/#sec-attested-credential-data
		AttestedCredentialDataConverter attestedCredentialDataConverter = findAttestedCredentialDataConverter();
		byte[] attestedCredentialDataBytes = pcp.getAttestedCredentialDataBytes();
		AttestedCredentialData attestedCredentialData = attestedCredentialDataConverter.convert(attestedCredentialDataBytes);

		if (!Arrays.equals(attestedCredentialId, attestedCredentialData.getCredentialId())) {
			// The stored credential ID in the attested credential data does not match the database's credential ID.
			// This is unexpected, and indicates the database has been tampered with.
			throw new HttpStatusException(HttpStatus.UNAUTHORIZED, "invalid credential ID");
		}

		CollectedClientData clientData = buildCollectedClientData(origin, pcp.getType(), savedAuthenticationChallenge);

		JsonConverter jsonConverter = findJsonConverter();
		// See https://webauthn4j.github.io/webauthn4j/en/#clientextensions
		AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> authenticatorExtensions = pcp.getAuthenticatorExtensionsJson() == null
				? null
				: jsonConverter.readValue(pcp.getAuthenticatorExtensionsJson(), AuthenticationExtensionsAuthenticatorOutputs.class);
		AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions = pcp.getClientExtensionsJson() == null
				? null
				: jsonConverter.readValue(pcp.getClientExtensionsJson(), AuthenticationExtensionsClientOutputs.class);

		Set<AuthenticatorTransport> transports = mapTransportStrings(pcp.getTransports());

		return new CredentialRecordImpl(
				attestationStatement,
				pcp.isUvInitialized(),
				pcp.isBackupEligible(),
				pcp.isBackupState(),
				pcp.getSignatureCount(),
				attestedCredentialData,
				authenticatorExtensions,
				clientData,
				clientExtensions,
				transports
		);
	}

	private static CollectedClientData buildCollectedClientData(
			Origin origin, String clientDataTypeStr, Challenge challenge
	) {
		ClientDataType clientDataType = ClientDataType.create(clientDataTypeStr);

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

	public static Set<AuthenticatorTransport> mapTransportStrings(List<String> transportStrs) {
		return transportStrs == null
				? null
				: transportStrs.stream().map(AuthenticatorTransport::create).collect(Collectors.toSet());
	}
}
