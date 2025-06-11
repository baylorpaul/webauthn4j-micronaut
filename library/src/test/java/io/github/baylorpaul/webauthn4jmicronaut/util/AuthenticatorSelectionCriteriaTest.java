package io.github.baylorpaul.webauthn4jmicronaut.util;

import com.webauthn4j.data.AuthenticatorSelectionCriteria;
import com.webauthn4j.data.ResidentKeyRequirement;
import com.webauthn4j.data.UserVerificationRequirement;
import io.micronaut.json.JsonMapper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;

public class AuthenticatorSelectionCriteriaTest {

	/**
	 * Check that even though AuthenticatorAttachment has a @JsonValue, it does not cause a NullPointerException for
	 * Micronaut Serialization when AuthenticatorAttachment is null inside a AuthenticatorSelectionCriteria.
	 */
	@Test
	public void testSerializeAuthenticatorSelectionCriteriaWithNullAuthenticatorAttachment() throws IOException {
		AuthenticatorSelectionCriteria val1 = new AuthenticatorSelectionCriteria(
				null,
				ResidentKeyRequirement.PREFERRED,
				UserVerificationRequirement.PREFERRED
		);

		// Serialize with Micronaut Serialization, not Jackson
		JsonMapper jsonMapper = JsonMapper.createDefault();
		String json = jsonMapper.writeValueAsString(val1);
		Assertions.assertEquals("{\"authenticatorAttachment\":null,\"requireResidentKey\":false,\"residentKey\":\"preferred\",\"userVerification\":\"preferred\"}", json);

		AuthenticatorSelectionCriteria val2 = jsonMapper.readValue(json, AuthenticatorSelectionCriteria.class);
		Assertions.assertNotNull(val2);
		Assertions.assertNull(val2.getAuthenticatorAttachment());
		Assertions.assertEquals(ResidentKeyRequirement.PREFERRED, val2.getResidentKey());
		Assertions.assertEquals(UserVerificationRequirement.PREFERRED, val2.getUserVerification());
	}
}
