package io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.serialization;

import com.webauthn4j.data.PublicKeyCredentialRequestOptions;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.PublicKeyCredentialRequestOptionsSessionDto;
import io.github.baylorpaul.webauthn4jmicronaut.util.PasskeyUtil;
import io.micronaut.json.JsonMapper;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

@MicronautTest
public class WebAuthn4JSerdeTest {

	@Inject
	private JsonMapper jsonMapper;

	@Test
	public void testJsonEncodingIsNotStringOfJson() throws IOException {
		PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions = PasskeyUtil.generateAuthenticationOptions(
				new DefaultChallenge(), List.of(), Duration.ofMinutes(5), "localhost"
		);

		PublicKeyCredentialRequestOptionsSessionDto input = new PublicKeyCredentialRequestOptionsSessionDto(
				UUID.randomUUID(),
				publicKeyCredentialRequestOptions
		);

		String jsonStr = jsonMapper.writeValueAsString(input);
		Assertions.assertNotNull(jsonStr);

		String searchStr = "\"publicKeyCredentialRequestOptions\":";
		int idx = jsonStr.indexOf(searchStr);
		String str = jsonStr.substring(idx + searchStr.length());

		// Test that the value for "publicKeyCredentialRequestOptions" is JSON, not a JSON string, since
		// PublicKeyCredentialRequestOptions.class is using GenericWebAuthn4JSerde, as configured in
		// WebAuthn4jSerdeConfig

		// Should be JSON, not string-ified JSON. E.g. we do NOT want it to look like:
		// {"challengeSessionId":"efbb7834-6e45-4bad-9087-ffd9ced3b837","publicKeyCredentialRequestOptions":"{\"challenge\":\"igsJfdvgQ4WVPF774QH7vg\",\"timeout\":300000,\"rpId\":\"localhost\",\"allowCredentials\":[],\"userVerification\":\"preferred\"}"}
		Assertions.assertFalse(str.startsWith("\"{\\\""));
		Assertions.assertTrue(str.startsWith("{\""));

		PublicKeyCredentialRequestOptionsSessionDto output = jsonMapper.readValue(jsonStr, PublicKeyCredentialRequestOptionsSessionDto.class);
		Assertions.assertNotNull(output);

		PublicKeyCredentialRequestOptions outputOpts = output.getPublicKeyCredentialRequestOptions();
		Assertions.assertNotNull(outputOpts);
		Assertions.assertEquals(
				input.getPublicKeyCredentialRequestOptions().getChallenge().toString(),
				outputOpts.getChallenge().toString()
		);
	}
}
