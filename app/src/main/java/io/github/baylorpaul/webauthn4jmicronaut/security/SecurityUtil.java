package io.github.baylorpaul.webauthn4jmicronaut.security;

import io.micronaut.http.HttpStatus;
import io.micronaut.http.exceptions.HttpStatusException;

import java.security.Principal;

public class SecurityUtil {

	public static long requireUserId(Principal principal) throws HttpStatusException {
		if (principal == null) {
			throw new HttpStatusException(HttpStatus.UNAUTHORIZED, "unable to find user ID while unauthenticated");
		}
		final String userIdStr = principal.getName();
		return Long.parseLong(userIdStr);
	}
}
