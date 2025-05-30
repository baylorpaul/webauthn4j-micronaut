package io.github.baylorpaul.webauthn4jmicronaut.security.passkey;

import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey;
import com.webauthn4j.data.extension.CredentialProtectionPolicy;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.CredentialPropertiesOutput;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import io.github.baylorpaul.webauthn4jmicronaut.security.jwt.TestCredentialsUtil;
import io.micronaut.json.JsonMapper;
import io.micronaut.serde.annotation.SerdeImport;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

@SerdeImport.Repeated({
		@SerdeImport(AuthenticatorTransport.class)
})
public class PasskeyTest {

	@Test
	public void testSerializedClientExtensions() {
		ObjectConverter objectConverter = new ObjectConverter();
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
		ObjectConverter objectConverter = new ObjectConverter();
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
		AttestedCredentialData attestedCredentialData = TestCredentialsUtil.buildFakeAttestedCredentialData();
		COSEKey origCoseKey = attestedCredentialData.getCOSEKey();
		final EC2COSEKey origEc2CoseKey;
		if (origCoseKey instanceof EC2COSEKey ec2CoseKey) {
			origEc2CoseKey = ec2CoseKey;
		} else {
			throw new IllegalArgumentException("Unsupported COSE key type: " + origCoseKey.getClass().getSimpleName());
		}

		ObjectConverter objectConverter = new ObjectConverter();
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
}
