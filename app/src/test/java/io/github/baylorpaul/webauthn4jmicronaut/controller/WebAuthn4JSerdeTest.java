package io.github.baylorpaul.webauthn4jmicronaut.controller;

import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.jackson.deserializer.cbor.COSEKeyEnvelope;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.CoreAuthenticationData;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey;
import com.webauthn4j.data.extension.CredentialProtectionPolicy;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.CredentialPropertiesOutput;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.verifier.internal.AssertionSignatureVerifier;
import io.github.baylorpaul.webauthn4jmicronaut.util.PasskeyTestUtil;
import io.github.baylorpaul.webauthn4jmicronaut.util.PasskeyUtil;
import io.micronaut.json.JsonMapper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Test serialization/deserialization of the WebAuthn4J library, including for native images and the @ReflectionConfig
 * entries: ./gradlew :app:nativeTest
 * Many of these tests could exist just in the library, but are here so that they may be tested against a native image,
 * in case any @ReflectionConfig is missing.
 */
public class WebAuthn4JSerdeTest {

	@Test
	public void testSerializedClientExtensions() {
		ObjectConverter objectConverter = PasskeyUtil.findObjectConverter();
		JsonConverter jsonConverter = objectConverter.getJsonConverter();

		AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions1 = new AuthenticationExtensionsClientOutputs.BuilderForRegistration()
				.build();
		AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions2 = new AuthenticationExtensionsClientOutputs.BuilderForRegistration()
				.setCredProps(new CredentialPropertiesOutput(true))
				.setHMACCreateSecret(true)
				.build();

		String serializedClientExtensions1 = jsonConverter.writeValueAsString(clientExtensions1);
		String serializedClientExtensions2 = jsonConverter.writeValueAsString(clientExtensions2);

		Assertions.assertEquals("{}", serializedClientExtensions1);
		Assertions.assertEquals("{\"credProps\":{\"rk\":true},\"hmacCreateSecret\":true}", serializedClientExtensions2);

		AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions3 = jsonConverter.readValue(serializedClientExtensions1, AuthenticationExtensionsClientOutputs.class);
		AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions4 = jsonConverter.readValue(serializedClientExtensions2, AuthenticationExtensionsClientOutputs.class);

		Assertions.assertNotNull(clientExtensions3);
		Assertions.assertNotNull(clientExtensions4);

		Assertions.assertNull(clientExtensions3.getCredProps());
		Assertions.assertNull(clientExtensions3.getHMACCreateSecret());

		Assertions.assertNotNull(clientExtensions4.getCredProps());
		Assertions.assertNotNull(clientExtensions4.getHMACCreateSecret());
		Assertions.assertEquals(true, clientExtensions4.getCredProps().getRk());
		Assertions.assertEquals(true, clientExtensions4.getHMACCreateSecret());
	}

	@Test
	public void testSerializedAuthenticatorExtensions() {
		ObjectConverter objectConverter = PasskeyUtil.findObjectConverter();
		JsonConverter jsonConverter = objectConverter.getJsonConverter();

		AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> authenticatorExtensions1 = new AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration()
				.build();
		AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> authenticatorExtensions2 = new AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration()
				.setCredProtect(CredentialProtectionPolicy.USER_VERIFICATION_REQUIRED)
				.setHMACCreateSecret(true)
				.build();

		String serializedAuthenticatorExtensions1 = jsonConverter.writeValueAsString(authenticatorExtensions1);
		String serializedAuthenticatorExtensions2 = jsonConverter.writeValueAsString(authenticatorExtensions2);

		Assertions.assertEquals("{}", serializedAuthenticatorExtensions1);
		Assertions.assertEquals("{\"credProtect\":3,\"hmac-secret\":true}", serializedAuthenticatorExtensions2);

		AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> authenticatorExtensions3 = jsonConverter.readValue(serializedAuthenticatorExtensions1, AuthenticationExtensionsAuthenticatorOutputs.class);
		AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> authenticatorExtensions4 = jsonConverter.readValue(serializedAuthenticatorExtensions2, AuthenticationExtensionsAuthenticatorOutputs.class);

		Assertions.assertNotNull(authenticatorExtensions3);
		Assertions.assertNotNull(authenticatorExtensions4);

		Assertions.assertNull(authenticatorExtensions3.getCredProtect());
		Assertions.assertNull(authenticatorExtensions3.getHMACCreateSecret());

		Assertions.assertNotNull(authenticatorExtensions4.getCredProtect());
		Assertions.assertNotNull(authenticatorExtensions4.getHMACCreateSecret());
		Assertions.assertEquals(CredentialProtectionPolicy.USER_VERIFICATION_REQUIRED, authenticatorExtensions4.getCredProtect());
		Assertions.assertEquals(true, authenticatorExtensions4.getHMACCreateSecret());
	}

	@Test
	public void testSerializeTransports() throws IOException {
		JsonMapper jsonMapper = JsonMapper.createDefault();
		Set<AuthenticatorTransport> transports = Set.of(AuthenticatorTransport.INTERNAL, AuthenticatorTransport.HYBRID);

		String serializedTransports = jsonMapper.writeValueAsString(transports);
		Assertions.assertNotNull(serializedTransports);

		String[] deserializedTransportsArr = jsonMapper.readValue(serializedTransports, String[].class);
		Assertions.assertNotNull(deserializedTransportsArr);
		List<String> deserializedTransports = Arrays.asList(deserializedTransportsArr);
		Assertions.assertEquals(transports.size(), deserializedTransports.size());
		Assertions.assertTrue(deserializedTransports.contains("internal"));
		Assertions.assertTrue(deserializedTransports.contains("hybrid"));
	}

	@Test
	public void testSerializeCOSEKey() {
		AttestedCredentialData attestedCredentialData = PasskeyTestUtil.generateAttestedCredentialData(false);
		COSEKey origCoseKey = attestedCredentialData.getCOSEKey();
		final EC2COSEKey origEc2CoseKey;
		if (origCoseKey instanceof EC2COSEKey ec2CoseKey) {
			origEc2CoseKey = ec2CoseKey;
		} else {
			throw new IllegalArgumentException("Unsupported COSE key type: " + origCoseKey.getClass().getSimpleName());
		}

		ObjectConverter objectConverter = PasskeyUtil.findObjectConverter();
		AttestedCredentialDataConverter attestedCredentialDataConverter = new AttestedCredentialDataConverter(objectConverter);

		// Convert to a byte array according to https://www.w3.org/TR/webauthn-1/#sec-attested-credential-data
		byte[] attestedCredentialDataBytes = attestedCredentialDataConverter.convert(attestedCredentialData);
		Assertions.assertNotNull(attestedCredentialDataBytes);

		// Decode the attested credential data byte array according to https://www.w3.org/TR/webauthn-1/#sec-attested-credential-data
		AttestedCredentialData resultCredData = attestedCredentialDataConverter.convert(attestedCredentialDataBytes);
		Assertions.assertNotNull(resultCredData);

		Assertions.assertEquals(attestedCredentialData.getAaguid(), resultCredData.getAaguid());
		Assertions.assertArrayEquals(attestedCredentialData.getCredentialId(), resultCredData.getCredentialId());

		COSEKey resultCoseKey = resultCredData.getCOSEKey();
		Assertions.assertNotNull(resultCoseKey);

		if (resultCoseKey instanceof EC2COSEKey resultEc2CoseKey) {
			Assertions.assertEquals(origEc2CoseKey.getKeyId(), resultEc2CoseKey.getKeyId());
			Assertions.assertEquals(origEc2CoseKey.getAlgorithm(), resultEc2CoseKey.getAlgorithm());
			Assertions.assertEquals(origEc2CoseKey.getKeyOps(), resultEc2CoseKey.getKeyOps());
			Assertions.assertEquals(origEc2CoseKey.getCurve(), resultEc2CoseKey.getCurve());
			Assertions.assertArrayEquals(origEc2CoseKey.getX(), resultEc2CoseKey.getX());
			Assertions.assertArrayEquals(origEc2CoseKey.getY(), resultEc2CoseKey.getY());
		} else {
			Assertions.fail("Unexpected key type: " + resultCoseKey.getClass().getSimpleName());
		}
	}

	@Test
	public void testAuthDataSignature() throws GeneralSecurityException {
		COSEKey coseKey = PasskeyTestUtil.generateCOSEKey(true);
		byte[] rawAuthenticatorData = "ab56def".getBytes();
		byte[] clientDataHash = "xy12mn".getBytes();

		byte[] signature = PasskeyTestUtil.generateAuthDataSignature(coseKey, rawAuthenticatorData, clientDataHash);

		CoreAuthenticationData authData = new CoreAuthenticationData(
				null,
				null,
				rawAuthenticatorData,
				clientDataHash,
				signature
		);
		new AssertionSignatureVerifier().verify(authData, coseKey);
	}

	/**
	 * Test serialization/deserialization of COSEKey
	 */
	@Test
	public void testCoseKeySerialization() {
		CborConverter cborConverter = PasskeyUtil.findObjectConverter().getCborConverter();
		COSEKey coseKeyIn = PasskeyTestUtil.generateCOSEKey(true);
		byte[] coseKeyBytes = cborConverter.writeValueAsBytes(coseKeyIn);

		Map<String, Object> coseKeyValuesMap = cborConverter.readValue(new ByteArrayInputStream(coseKeyBytes), java.util.Map.class);

		// Check that the values are mapped correctly, especially for native builds that require @ReflectiveAccess (or
		// @ReflectionConfig if it's a library that can't be changed). Otherwise, values such as those configured via
		// @JsonSubTypes, will not be mapped correctly. E.g. @JsonSubTypes in COSEKey.java or @JsonProperty in
		// EC2COSEKey.java.
		// See https://github.com/micronaut-projects/micronaut-core/issues/6672

		// On a COSEKey, the @JsonTypeInfo specifies a "1" property, where EC2COSEKey is "2"
		Assertions.assertEquals(2, coseKeyValuesMap.get("1"));
		// On a EC2COSEKey, the "curve" is a @JsonProperty("-1"), where SECP256R1 has a value of 1
		Assertions.assertEquals(1, coseKeyValuesMap.get("-1"));

		COSEKeyEnvelope envOut = cborConverter.readValue(new ByteArrayInputStream(coseKeyBytes), COSEKeyEnvelope.class);
		Assertions.assertNotNull(envOut);
		COSEKey coseKeyOut = envOut.getCOSEKey();
		Assertions.assertNotNull(coseKeyOut);
		Assertions.assertEquals(coseKeyBytes.length, envOut.getLength());

		PublicKey pkIn = coseKeyIn.getPublicKey();
		PublicKey pkOut = coseKeyOut.getPublicKey();
		Assertions.assertNotNull(pkIn);
		Assertions.assertNotNull(pkOut);

		Assertions.assertEquals(pkIn.getAlgorithm(), pkOut.getAlgorithm());
		Assertions.assertEquals(pkIn.getFormat(), pkOut.getFormat());
		Assertions.assertArrayEquals(pkIn.getEncoded(), pkOut.getEncoded());

		Assertions.assertEquals(coseKeyIn.getKeyType(), coseKeyOut.getKeyType());
		Assertions.assertArrayEquals(coseKeyIn.getKeyId(), coseKeyOut.getKeyId());
		Assertions.assertEquals(coseKeyIn.getAlgorithm(), coseKeyOut.getAlgorithm());
	}
}
