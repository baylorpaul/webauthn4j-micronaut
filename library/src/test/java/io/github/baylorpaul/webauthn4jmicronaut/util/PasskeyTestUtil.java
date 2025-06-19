package io.github.baylorpaul.webauthn4jmicronaut.util;

import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.*;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.MessageDigestUtil;
import io.github.baylorpaul.webauthn4jmicronaut.security.PasskeyConfiguration;
import io.github.baylorpaul.webauthn4jmicronaut.security.passkey.model.PasskeyCredAndUserHandle;
import io.micronaut.core.annotation.NonNull;
import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class PasskeyTestUtil {
	private static final String SAMPLE_AAGUID = "fbfc3007-154e-4ecc-8c0b-6e020557d7bd";

	/**
	 * @param includePrivateKey true to include the private key. Note that the backend should never have the private
	 *            key. Some frontend tests need the private key to sign data.
	 */
	public static CredentialRecord generateCredentialRecord(
			@NonNull String originUrl, @NonNull Challenge savedChallenge, boolean includePrivateKey
	) {
		AttestationStatement attestationStatement = new NoneAttestationStatement();
		Boolean uvInitialized = true;
		Boolean backupEligible = true;
		Boolean backupState = true;
		long counter = 0L;

		AttestedCredentialData attestedCredentialData = generateAttestedCredentialData(includePrivateKey);

		AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> authenticatorExtensions = new AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration()
				.build();
		Origin origin = new Origin(originUrl);
		CollectedClientData clientData = new CollectedClientData(
				ClientDataType.WEBAUTHN_CREATE,
				savedChallenge,
				origin,
				null,
				null
		);
		AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions = new AuthenticationExtensionsClientOutputs.BuilderForRegistration()
				.build();
		Set<AuthenticatorTransport> transports = Set.of(AuthenticatorTransport.INTERNAL, AuthenticatorTransport.HYBRID);

		return new CredentialRecordImpl(
				attestationStatement,
				uvInitialized,
				backupEligible,
				backupState,
				counter,
				attestedCredentialData,
				authenticatorExtensions,
				clientData,
				clientExtensions,
				transports
		);
	}

	public static @NonNull CredentialRecord cloneCredentialRecordWithoutPrivateKey(CredentialRecord orig) {
		if (orig.getAttestationStatement() == null) {
			throw new IllegalArgumentException("attestationStatement must not be null");
		} else if (orig.getAuthenticatorExtensions() == null) {
			throw new IllegalArgumentException("authenticatorExtensions must not be null");
		}

		AttestedCredentialData newAttestedCredentialData = cloneAttestedCredentialDataWithoutPrivateKey(
				orig.getAttestedCredentialData()
		);

		return new CredentialRecordImpl(
				orig.getAttestationStatement(),
				orig.isUvInitialized(),
				orig.isBackupEligible(),
				orig.isBackedUp(),
				orig.getCounter(),
				newAttestedCredentialData,
				orig.getAuthenticatorExtensions(),
				orig.getClientData(),
				orig.getClientExtensions(),
				orig.getTransports()
		);
	}

	private static @NonNull AttestedCredentialData cloneAttestedCredentialDataWithoutPrivateKey(
			AttestedCredentialData orig
	) {
		COSEKey origCoseKey = orig.getCOSEKey();

		final COSEKey coseKeyWithoutPrivateKey;
		if (origCoseKey instanceof EC2COSEKey origEc2COSEKey) {
			coseKeyWithoutPrivateKey = new EC2COSEKey(
					origEc2COSEKey.getKeyId(),
					origEc2COSEKey.getAlgorithm(),
					origEc2COSEKey.getKeyOps(),
					origEc2COSEKey.getCurve(),
					origEc2COSEKey.getX(),
					origEc2COSEKey.getY(),
					// Excluding "d" (private key)
					null
			);
		} else {
			throw new IllegalArgumentException("Only EC2COSEKey is supported for this test method");
		}

		return new AttestedCredentialData(
				orig.getAaguid(),
				orig.getCredentialId(),
				coseKeyWithoutPrivateKey
		);
	}

	/**
	 * @param includePrivateKey true to include the private key. Note that the backend should never have the private
	 *            key. Some frontend tests need the private key to sign data.
	 */
	public static COSEKey generateCOSEKey(boolean includePrivateKey) {
		// "x" and "y" are the public key. "d" is the private key.

		// Initialize KeyPairGenerator for EC with P-256 curve
		final KeyPairGenerator keyGen;
		try {
			keyGen = KeyPairGenerator.getInstance("EC");
			ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1"); // NIST P-256
			keyGen.initialize(ecSpec, new SecureRandom());
		} catch (GeneralSecurityException e) {
			throw new RuntimeException("Failed to initialize KeyPairGenerator", e);
		}

		KeyPair keyPair = keyGen.generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();

		ECPrivateKey ecPrivateKey = (ECPrivateKey) privateKey;
		ECPublicKey ecPublicKey = (ECPublicKey) publicKey;

		byte[] privateKeyD = ecPrivateKey.getS().toByteArray();
		byte[] publicKeyX = ecPublicKey.getW().getAffineX().toByteArray();
		byte[] publicKeyY = ecPublicKey.getW().getAffineY().toByteArray();

		// Ensure each are 32 bytes (pad or trim if necessary)
		privateKeyD = normalizeTo32Bytes(privateKeyD);
		publicKeyX = normalizeTo32Bytes(publicKeyX);
		publicKeyY = normalizeTo32Bytes(publicKeyY);

		return new EC2COSEKey(
				null,
				COSEAlgorithmIdentifier.ES256,
				null,
				Curve.SECP256R1,
				publicKeyX,
				publicKeyY,
				includePrivateKey ? privateKeyD : null
		);
	}

	/**
	 * Utility method to normalize byte arrays to exactly 32 bytes
	 */
	private static byte[] normalizeTo32Bytes(byte[] input) {
		if (input.length == 32) {
			return input;
		}
		byte[] output = new byte[32];
		if (input.length > 32) {
			// Trim leading bytes (big-endian, keep last 32 bytes)
			System.arraycopy(input, input.length - 32, output, 0, 32);
		} else {
			// Pad with leading zeros
			System.arraycopy(input, 0, output, 32 - input.length, input.length);
		}
		return output;
	}

	public static byte[] generateCredentialId() {
		SecureRandom random = new SecureRandom();
		byte[] credentialId = new byte[20];
		random.nextBytes(credentialId);
		return credentialId;
	}

	/**
	 * @param includePrivateKey true to include the private key. Note that the backend should never have the private
	 *            key. Some frontend tests need the private key to sign data.
	 */
	public static AttestedCredentialData generateAttestedCredentialData(boolean includePrivateKey) {
		byte[] attestedCredentialId = generateCredentialId();
		return generateAttestedCredentialData(attestedCredentialId, includePrivateKey);
	}

	/**
	 * @param includePrivateKey true to include the private key. Note that the backend should never have the private
	 *            key. Some frontend tests need the private key to sign data.
	 */
	public static AttestedCredentialData generateAttestedCredentialData(byte[] credentialId, boolean includePrivateKey) {
		AAGUID aaguid = new AAGUID(SAMPLE_AAGUID);
		COSEKey coseKey = generateCOSEKey(includePrivateKey);
		return new AttestedCredentialData(aaguid, credentialId, coseKey);
	}

	private static byte[] findRpIdHash(String rpId) {
		byte[] relyingPartyRpIdBytes = rpId.getBytes(StandardCharsets.UTF_8);
		return MessageDigestUtil.createSHA256().digest(relyingPartyRpIdBytes);
	}

	public static String createAttestationObjectBase64UrlEncoded(
			@NonNull @NotBlank String rpId, byte[] credentialId
	) {
		byte[] rpIdHash = findRpIdHash(rpId);
		AttestedCredentialData attestedCredentialData = generateAttestedCredentialData(credentialId, false);
		// 93 = bits 1011101 - See https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data
		byte flags = 93;
		AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(
				rpIdHash,
				flags,
				0L,
				attestedCredentialData,
				new AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration()
						.build()
		);
		AttestationStatement attestationStatement = new NoneAttestationStatement();

		AttestationObject attestationObject = new AttestationObject(authenticatorData, attestationStatement);

		ObjectConverter objectConverter = PasskeyUtil.findObjectConverter();
		AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter(objectConverter);
		return attestationObjectConverter.convertToBase64urlString(attestationObject);
	}

	public static String createClientDataForPasskeyCreateBase64UrlEncoded(
			@NonNull @NotBlank String originUrl, Challenge challenge
	) {
		CollectedClientData ccd = new CollectedClientData(
				ClientDataType.WEBAUTHN_CREATE,
				challenge,
				new Origin(originUrl),
				false,
				null
		);

		ObjectConverter objectConverter = PasskeyUtil.findObjectConverter();
		CollectedClientDataConverter collectedClientDataConverter = new CollectedClientDataConverter(objectConverter);
		return collectedClientDataConverter.convertToBase64UrlString(ccd);
	}

	public static byte[] createClientDataForPasskeyGet(
			@NonNull @NotBlank String originUrl, Challenge challenge
	) {
		CollectedClientData ccd = new CollectedClientData(
				ClientDataType.WEBAUTHN_GET,
				challenge,
				new Origin(originUrl),
				false,
				null
		);

		ObjectConverter objectConverter = PasskeyUtil.findObjectConverter();
		CollectedClientDataConverter collectedClientDataConverter = new CollectedClientDataConverter(objectConverter);
		return collectedClientDataConverter.convertToBytes(ccd);
	}

	/**
	 * @param clientDataHash the SHA-256 hash of the client data
	 */
	public static byte[] generateAuthDataSignature(
			COSEKey coseKey, byte[] rawAuthenticatorData, byte[] clientDataHash
	) throws GeneralSecurityException {
		PrivateKey privateKey = coseKey.getPrivateKey();
		if (privateKey == null) {
			throw new GeneralSecurityException("Cannot generate signature without a private key");
		}

		// Using the privateKey, encrypt the binary concatenation of authData and hash. See AssertionSignatureVerifier.java
		byte[] signedData = ByteBuffer
				.allocate(rawAuthenticatorData.length + clientDataHash.length)
				.put(rawAuthenticatorData)
				.put(clientDataHash)
				.array();

		SignatureAlgorithm signatureAlgorithm = coseKey.getAlgorithm().toSignatureAlgorithm();
		String jcaName = signatureAlgorithm.getJcaName();
		Signature signer = Signature.getInstance(jcaName);
		signer.initSign(privateKey);
		signer.update(signedData);
		return signer.sign();
	}

	public static String createAuthenticatorDataForPasskeyCreateBase64UrlEncoded(
			@NonNull @NotBlank String rpId, byte[] credentialId
	) {
		byte[] rpIdHash = findRpIdHash(rpId);
		AttestedCredentialData attestedCredentialData = generateAttestedCredentialData(credentialId, false);
		// 93 = bits 1011101 - See https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data
		byte flags = 93;
		AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(
				rpIdHash, flags, 0L, attestedCredentialData
		);

		ObjectConverter objectConverter = PasskeyUtil.findObjectConverter();
		AuthenticatorDataConverter authenticatorDataConverter = new AuthenticatorDataConverter(objectConverter);
		byte[] authDataByteArray = authenticatorDataConverter.convert(authenticatorData);
		return Base64UrlUtil.encodeToString(authDataByteArray);
	}

	public static byte[] createAuthenticatorDataForPasskeyGet(
			@NonNull @NotBlank String rpId
	) {
		byte[] rpIdHash = findRpIdHash(rpId);
		// 29 = bits 0011101 - See https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data
		byte flags = 29;
		AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(
				rpIdHash,
				flags,
				0L,
				null,
				new AuthenticationExtensionsAuthenticatorOutputs.BuilderForAuthentication()
						.build()
		);

		ObjectConverter objectConverter = PasskeyUtil.findObjectConverter();
		AuthenticatorDataConverter authenticatorDataConverter = new AuthenticatorDataConverter(objectConverter);
		return authenticatorDataConverter.convert(authenticatorData);
	}

	/**
	 * Simulate a call to navigator.credentials.create() in the browser/authenticator.
	 * @param challengeOverride null to use the challenge from the creation options, else a challenge to use as an
	 *            override to test different scenarios
	 * @return a simulated object representing a "registrationResponse"
	 */
	public static Map<String, Object> generatePasskeyRegistrationResponse(
			@NotNull PasskeyConfiguration passkeyConfiguration,
			@NotNull PublicKeyCredentialCreationOptions creationOptions, @Nullable Challenge challengeOverride
	) {
		COSEKey coseKey = generateCOSEKey(false);
		PublicKey publicKey = coseKey.getPublicKey();
		return generatePasskeyRegistrationResponse(passkeyConfiguration, creationOptions, challengeOverride, publicKey);
	}

	/**
	 * Simulate a call to navigator.credentials.create() in the browser/authenticator.
	 * @param challengeOverride null to use the challenge from the creation options, else a challenge to use as an
	 *            override to test different scenarios
	 * @return a simulated object representing a "registrationResponse"
	 */
	public static Map<String, Object> generatePasskeyRegistrationResponse(
			@NotNull PasskeyConfiguration passkeyConfiguration,
			@NotNull PublicKeyCredentialCreationOptions creationOptions, @Nullable Challenge challengeOverride,
			@NotNull PublicKey publicKey
	) {
		byte[] credentialId = generateCredentialId();
		String base64UrlId = Base64UrlUtil.encodeToString(credentialId);
		Challenge challenge = challengeOverride == null ? creationOptions.getChallenge() : challengeOverride;

		Map<String, Object> registrationResponse = new LinkedHashMap<>();
		registrationResponse.put("id", base64UrlId);
		registrationResponse.put("rawId", base64UrlId);

		String publicKeyBase64Url = publicKey == null ? null : Base64UrlUtil.encodeToString(publicKey.getEncoded());

		// Note: For "registration", the challenge does not need to be signed by the private key when using "none"
		// attestation method. That's why we don't need to use the private key here. And that's why the server is not
		// expecting a signature that includes the challenge during registration. It's a different story for
		// "authentication", where the "signature" is required.
		// See https://github.com/w3c/webauthn/issues/1355

		Map<String, Object> response = new LinkedHashMap<>();
		response.put("attestationObject", createAttestationObjectBase64UrlEncoded(passkeyConfiguration.getRpId(), credentialId));
		response.put("clientDataJSON", createClientDataForPasskeyCreateBase64UrlEncoded(passkeyConfiguration.getOriginUrl(), challenge));
		response.put("transports", List.of(AuthenticatorTransport.HYBRID.getValue(), AuthenticatorTransport.INTERNAL.getValue()));
		response.put("publicKeyAlgorithm", COSEAlgorithmIdentifier.ES256.getValue());
		// Hardcoded public key
		response.put("publicKey", publicKeyBase64Url);
		response.put("authenticatorData", createAuthenticatorDataForPasskeyCreateBase64UrlEncoded(passkeyConfiguration.getRpId(), credentialId));
		registrationResponse.put("response", response);

		registrationResponse.put("type", PublicKeyCredentialType.PUBLIC_KEY.getValue());
		registrationResponse.put("clientExtensionResults", Map.of());
		registrationResponse.put("authenticatorAttachment", AuthenticatorAttachment.PLATFORM.getValue());

		return registrationResponse;
	}

	/**
	 * Simulate a call to navigator.credentials.get() in the browser/authenticator.
	 * @param challengeOverride null to use the challenge from the creation options, else a challenge to use as an
	 *            override to test different scenarios
	 * @return a simulated object representing an "authenticationResponse"
	 */
	public static Map<String, Object> generatePasskeyAuthenticationResponse(
			@NotNull PasskeyConfiguration passkeyConfiguration,
			@NotNull PublicKeyCredentialRequestOptions requestOptions,
			@NotNull PasskeyCredAndUserHandle credAndUserHandle, @Nullable Challenge challengeOverride
	) {
		AttestedCredentialData attestedCredentialData = credAndUserHandle.attestedCredentialDataIncludingPrivateKey();
		byte[] credentialId = attestedCredentialData.getCredentialId();
		Challenge challenge = challengeOverride == null ? requestOptions.getChallenge() : challengeOverride;

		return generatePasskeyAuthenticationResponse(
				passkeyConfiguration,
				credAndUserHandle.userHandleBase64Url(),
				Base64UrlUtil.encodeToString(credentialId),
				attestedCredentialData.getCOSEKey(),
				challenge
		);
	}

	/**
	 * Simulate a call to navigator.credentials.get() in the browser/authenticator.
	 * @return a simulated object representing an "authenticationResponse"
	 */
	public static Map<String, Object> generatePasskeyAuthenticationResponse(
			@NotNull PasskeyConfiguration passkeyConfiguration,
			@NotNull String userHandleBase64Url, @NotNull String base64UrlCredentialId, @NotNull COSEKey coseKey,
			@Nullable Challenge challenge
	) {
		Map<String, Object> authenticationResponse = new LinkedHashMap<>();
		authenticationResponse.put("id", base64UrlCredentialId);
		authenticationResponse.put("rawId", base64UrlCredentialId);

		byte[] rawAuthenticatorData = createAuthenticatorDataForPasskeyGet(passkeyConfiguration.getRpId());
		byte[] clientData = createClientDataForPasskeyGet(passkeyConfiguration.getOriginUrl(), challenge);
		byte[] clientDataHash = MessageDigestUtil.createSHA256().digest(clientData);

		final String signatureBase64Url;
		try {
			byte[] signature = generateAuthDataSignature(coseKey, rawAuthenticatorData, clientDataHash);
			signatureBase64Url = Base64UrlUtil.encodeToString(signature);
		} catch (GeneralSecurityException e) {
			throw new RuntimeException("Unable to generate a signature", e);
		}

		Map<String, Object> response = new LinkedHashMap<>();
		response.put("authenticatorData", Base64UrlUtil.encodeToString(rawAuthenticatorData));
		response.put("clientDataJSON", Base64UrlUtil.encodeToString(clientData));
		response.put("signature", signatureBase64Url);
		response.put("userHandle", userHandleBase64Url);
		authenticationResponse.put("response", response);

		authenticationResponse.put("type", PublicKeyCredentialType.PUBLIC_KEY.getValue());
		authenticationResponse.put("clientExtensionResults", Map.of());
		authenticationResponse.put("authenticatorAttachment", AuthenticatorAttachment.PLATFORM.getValue());

		return authenticationResponse;
	}
}
