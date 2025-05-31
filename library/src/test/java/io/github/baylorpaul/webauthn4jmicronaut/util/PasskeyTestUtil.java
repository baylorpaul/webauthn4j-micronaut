package io.github.baylorpaul.webauthn4jmicronaut.util;

import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.SignatureAlgorithm;
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
import io.micronaut.core.annotation.NonNull;
import jakarta.validation.constraints.NotBlank;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
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
		AttestedCredentialData attestedCredentialData = PasskeyTestUtil.generateAttestedCredentialData(credentialId, false);
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
		AttestedCredentialData attestedCredentialData = PasskeyTestUtil.generateAttestedCredentialData(credentialId, false);
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
}
