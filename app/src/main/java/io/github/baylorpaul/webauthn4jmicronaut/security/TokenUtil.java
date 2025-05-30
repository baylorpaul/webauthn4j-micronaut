package io.github.baylorpaul.webauthn4jmicronaut.security;

import com.nimbusds.jwt.JWTClaimNames;
import io.github.baylorpaul.webauthn4jmicronaut.entity.User;
import io.github.baylorpaul.webauthn4jmicronaut.service.model.ConfirmationRequest;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.util.CollectionUtils;
import io.micronaut.security.authentication.ServerAuthentication;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

public class TokenUtil {

	public static final String CLAIM_NAME_CONFIRMATION_TYPE = "confirmation_type";
	public static final String CLAIM_NAME_EMAIL = "email";
	/**
	 * A random value to ensure the same JWT is not re-generated if re-attempted at the same second. This is mostly
	 * only a concern for unit tests.
	 */
	private static final String CLAIM_NAME_RANDOM = "jwt_r";

	/**
	 * Build a user authentication for a confirmation request. E.g. email verification, password reset, unsubscribe
	 */
	public static ServerAuthentication buildAuthenticationForConfirmationRequest(
			@NonNull User user, ConfirmationRequest confReq
	) {
		Map<String, Object> claims = new LinkedHashMap<>(
				buildConfirmationRequestJwtClaims(user)
		);
		claims.put(CLAIM_NAME_CONFIRMATION_TYPE, confReq.getType().toString());
		claims.put(CLAIM_NAME_EMAIL, confReq.getEmail());

		// Generate a random value to ensure the same JWT is not re-generated if re-attempted at the same second
		claims.put(CLAIM_NAME_RANDOM, new SecureRandom().nextInt());

		if (!CollectionUtils.isEmpty(confReq.getAdditionalJwtClaims())) {
			claims.putAll(confReq.getAdditionalJwtClaims());
		}
		return new ServerAuthentication(
				// When using an access token, the user ID is provided for the principal name, as indicated in the "sub" claim.
				Long.toString(user.getId()),
				Collections.emptyList(),
				claims
		);
	}

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

	/**
	 * Build JSON Web Token Claims for a confirmation request. E.g. email verification, password reset, unsubscribe
	 * @see <a href="https://www.iana.org/assignments/jwt/jwt.xhtml">JSON Web Token Claims</a>
	 */
	public static Map<String, Object> buildConfirmationRequestJwtClaims(@NonNull User user) {
		Map<String, Object> attributes = new LinkedHashMap<>();
		attributes.put(JWTClaimNames.SUBJECT, Long.toString(user.getId()));
		return attributes;
	}

	public static Long findJwtSubjectAsUserId(@NonNull Map<String, ?> jwtClaims) throws NumberFormatException {
		final Object subObj = jwtClaims.get(JWTClaimNames.SUBJECT);
		if (subObj instanceof String subStr) {
			return Long.parseLong(subStr);
		} else if (subObj != null) {
			throw new RuntimeException("Unexpected object type for 'sub' claim: " + subObj.getClass().getCanonicalName());
		} else {
			return null;
		}
	}

	public static Instant findJwtExpirationDate(@NonNull Map<String, ?> jwtClaims) {
		final Instant expiration;
		final Object expObj = jwtClaims.get(JWTClaimNames.EXPIRATION_TIME);
		if (expObj instanceof Date expDate) {
			// Normally "exp" is an epoch second, but JWTClaimsSet.parse() will return a Date
			expiration = expDate.toInstant();
		} else if (expObj instanceof Number expSecond) {
			expiration = Instant.ofEpochSecond(expSecond.longValue());
		} else if (expObj != null) {
			throw new RuntimeException("Unexpected object type for 'exp' claim: " + expObj.getClass().getCanonicalName());
		} else {
			expiration = null;
		}
		return expiration;
	}
}
