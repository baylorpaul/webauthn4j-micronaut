package io.github.baylorpaul.webauthn4jmicronaut.security.passkey;

import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey;
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
