package io.github.baylorpaul.webauthn4jmicronaut.security;

import io.github.baylorpaul.webauthn4jmicronaut.security.model.AuthenticationUserInfo;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.authentication.AuthenticationException;
import io.micronaut.security.authentication.AuthenticationFailed;
import io.micronaut.security.authentication.AuthenticationFailureReason;
import io.micronaut.security.authentication.AuthenticationResponse;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.List;

/**
 * WARNING! This does NOT do any credential verification.
 * This is an authentication provider for users whose credentials have already been verified.
 * This does NOT implement HttpRequestAuthenticationProvider, so it is not used for login requests from e.g.
 * io.micronaut.security.endpoints.LoginController.
 */
public class AuthenticationProviderForPreVerifiedCredentials {

	/**
	 * WARNING! This does NOT do any credential verification.
	 * For when a user's credentials have already been verified, generate an authentication response.
	 */
	public static Mono<AuthenticationResponse> generateAuthenticationResponseForPreVerifiedCredentials(@Nullable AuthenticationUserInfo userInfo) {
		// Similar to Micronaut Security's io.micronaut.security.authentication.Authenticator, except we're not going to
		// implement an HttpRequestAuthenticationProvider, since we don't want that to execute under any other
		// circumstances.
		return Mono.just(generateAuthenticationResponse(userInfo))
				.flatMap(AuthenticationProviderForPreVerifiedCredentials::handleResponse)
				.switchIfEmpty(Mono.error(() -> new AuthenticationException("Provider did not respond. Authentication rejected")))
				.onErrorResume(t -> Mono.just(authenticationResponseForThrowable(t)));
	}

	/**
	 * Generate an authentication response for a user after their credentials have already been validated
	 */
	public static @NonNull AuthenticationResponse generateAuthenticationResponse(@Nullable AuthenticationUserInfo userInfo) {
		AuthenticationFailureReason authenticationFailureReason = checkForFailureReason(userInfo);

		if (authenticationFailureReason == null) {
			return AuthenticationResponse.success(
					userInfo.getUserId(),
					userInfo.getUserRoles() == null ? Collections.emptyList() : userInfo.getUserRoles(),
					userInfo.getUserAttributes() == null ? Collections.emptyMap() : userInfo.getUserAttributes()
			);
		} else {
			return AuthenticationResponse.failure(authenticationFailureReason);
		}
	}

	private static Mono<AuthenticationResponse> handleResponse(AuthenticationResponse response) {
		if (response.isAuthenticated()) {
			return Mono.just(response);
		} else {
			return Mono.error(new AuthenticationException(response));
		}
	}

	@NonNull
	private static AuthenticationResponse authenticationResponseForThrowable(Throwable t) {
		if (Exceptions.isMultiple(t)) {
			List<Throwable> exceptions = Exceptions.unwrapMultiple(t);
			return new AuthenticationFailed(exceptions.get(exceptions.size() - 1).getMessage());
		}
		return new AuthenticationFailed(t.getMessage());
	}

	private static AuthenticationFailureReason checkForFailureReason(@Nullable AuthenticationUserInfo userInfo) {
		AuthenticationFailureReason authenticationFailureReason = null;
		if (userInfo == null) {
			authenticationFailureReason = AuthenticationFailureReason.USER_NOT_FOUND;
		} else if (!userInfo.isEnabled()) {
			authenticationFailureReason = AuthenticationFailureReason.USER_DISABLED;
		}
		return authenticationFailureReason;
	}
}
