package io.github.baylorpaul.webauthn4jmicronaut.security;

import com.nimbusds.jwt.JWTClaimNames;
import io.micronaut.core.annotation.NonNull;

import java.util.LinkedHashMap;
import java.util.Map;

public class TokenUtil {

	public static final String CLAIM_NAME_EMAIL = "email";

	/**
	 * Build JSON Web Token Claims
	 * @see <a href="https://www.iana.org/assignments/jwt/jwt.xhtml">JSON Web Token Claims</a>
	 */
	public static Map<String, Object> buildJwtClaims(@NonNull io.github.baylorpaul.webauthn4jmicronaut.entity.User user) {
		Map<String, Object> attributes = new LinkedHashMap<>();

		// Override "sub". This is the ServerAuthentication.name otherwise.
		// The "sub" becomes the "name" on the Principal
		attributes.put(JWTClaimNames.SUBJECT, Long.toString(user.getId()));

		attributes.put(CLAIM_NAME_EMAIL, user.getEmail());
		attributes.put("name", user.getName());
		return attributes;
	}
}
