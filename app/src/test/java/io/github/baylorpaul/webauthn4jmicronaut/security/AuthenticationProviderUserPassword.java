package io.github.baylorpaul.webauthn4jmicronaut.security;

import io.github.baylorpaul.webauthn4jmicronaut.entity.User;
import io.github.baylorpaul.webauthn4jmicronaut.repo.UserRepository;
import io.github.baylorpaul.webauthn4jmicronaut.util.EmailUtil;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.AuthenticationFailureReason;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.provider.HttpRequestAuthenticationProvider;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;

@Singleton
public class AuthenticationProviderUserPassword implements HttpRequestAuthenticationProvider<HttpRequest<?>> {

	private static final Logger log = LoggerFactory.getLogger(AuthenticationProviderUserPassword.class);

	@Inject
	private UserRepository userRepo;

	@Override
	public @NonNull AuthenticationResponse authenticate(
			@Nullable HttpRequest<HttpRequest<?>> requestContext,
			@NonNull AuthenticationRequest<String, String> authenticationRequest
	) {
		String email = authenticationRequest.getIdentity();
		email = EmailUtil.formatEmailAddress(email);
		User user = email == null ? null : userRepo.findByEmail(email).orElse(null);

		// TODO check that the "rawPassword" matches the user's password.
		//  See https://guides.micronaut.io/latest/micronaut-database-authentication-provider-gradle-groovy.html#authentication-provider
		log.error("There is NO SECURITY for password matching! Any value is accepted as valid.");
		String rawPassword = authenticationRequest.getSecret().toString();
		boolean passwordMatches = true;

		if (passwordMatches) {
			return AuthenticationResponse.success(
					Long.toString(user.getId()),
					Collections.emptyList(),
					// Even though we used BASIC authorization to get here, we are providing future authorization via an access token
					TokenUtil.buildJwtClaims(user)
			);
		} else {
			return AuthenticationResponse.failure(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH);
		}
	}
}
