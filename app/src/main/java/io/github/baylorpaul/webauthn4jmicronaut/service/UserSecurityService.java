package io.github.baylorpaul.webauthn4jmicronaut.service;

import io.micronaut.context.event.ApplicationEventPublisher;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.server.util.HttpHostResolver;
import io.micronaut.http.server.util.locale.HttpLocaleResolver;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.event.LoginFailedEvent;
import io.micronaut.security.event.LoginSuccessfulEvent;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

@Singleton
public class UserSecurityService {

	@Inject
	private ApplicationEventPublisher<LoginSuccessfulEvent> loginSuccessfulEventPublisher;

	@Inject
	private ApplicationEventPublisher<LoginFailedEvent> loginFailedEventPublisher;

	@Inject
	private HttpHostResolver httpHostResolver;

	@Inject
	private HttpLocaleResolver httpLocaleResolver;

	public void publishLoginSuccess(Authentication authentication, HttpRequest<?> request) {
		loginSuccessfulEventPublisher.publishEvent(
				new LoginSuccessfulEvent(
						authentication,
						httpHostResolver.resolve(request),
						httpLocaleResolver.resolveOrDefault(request)
				)
		);
	}

	public void publishLoginFailed(
			@Nullable AuthenticationRequest authenticationRequest, AuthenticationResponse authenticationResponse,
			HttpRequest<?> request
	) {
		loginFailedEventPublisher.publishEvent(
				new LoginFailedEvent(
						authenticationResponse,
						authenticationRequest,
						httpHostResolver.resolve(request),
						httpLocaleResolver.resolveOrDefault(request)
				)
		);
	}
}
