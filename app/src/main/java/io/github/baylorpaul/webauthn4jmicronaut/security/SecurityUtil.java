package io.github.baylorpaul.webauthn4jmicronaut.security;

import io.github.baylorpaul.webauthn4jmicronaut.security.validator.ConfirmationJsonWebTokenValidator;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.exceptions.HttpStatusException;
import io.micronaut.security.authentication.Authentication;

import java.security.Principal;
import java.util.Optional;

public class SecurityUtil {

	public static long requireUserId(Principal principal) throws HttpStatusException {
		if (principal == null) {
			throw new HttpStatusException(HttpStatus.UNAUTHORIZED, "unable to find user ID while unauthenticated");
		}
		final String userIdStr = principal.getName();
		return Long.parseLong(userIdStr);
	}

	/**
	 * Ensure the token is a confirmation token (e.g. not an access token), and that it is appropriately signed & valid
	 * @param confirmationToken the confirmation JWT
	 * @return the valid confirmation token, or null if the token is not appropriately signed & valid, or it's not a confirmation token
	 */
	public static Optional<Authentication> validateConfirmationJwt(
			ConfirmationJsonWebTokenValidator<?> confirmationJsonWebTokenValidator, String confirmationToken
	) {
		// Ensure the token is appropriately signed & valid. A PlainJWT is not considered valid unless there are no
		// signature configurations, and there should be signature configurations.
		return confirmationJsonWebTokenValidator.validateToken(confirmationToken, null);
	}
}
