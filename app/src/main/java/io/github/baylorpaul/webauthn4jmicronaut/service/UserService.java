package io.github.baylorpaul.webauthn4jmicronaut.service;

import io.github.baylorpaul.webauthn4jmicronaut.ApplicationConfigurationProperties;
import io.github.baylorpaul.webauthn4jmicronaut.entity.User;
import io.github.baylorpaul.webauthn4jmicronaut.repo.UserRepository;
import io.github.baylorpaul.webauthn4jmicronaut.security.TokenUtil;
import io.github.baylorpaul.webauthn4jmicronaut.service.mail.MailTemplateService;
import io.github.baylorpaul.webauthn4jmicronaut.service.mail.template.PasskeyAdditionLinkEmailTemplate;
import io.github.baylorpaul.webauthn4jmicronaut.service.model.ConfirmationRequest;
import io.github.baylorpaul.webauthn4jmicronaut.service.model.enums.ConfirmationType;
import io.github.baylorpaul.webauthn4jmicronaut.util.EmailUtil;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.email.Contact;
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.security.authentication.ServerAuthentication;
import io.micronaut.security.token.generator.TokenGenerator;
import io.micronaut.security.token.render.AccessRefreshToken;
import io.micronaut.security.token.render.TokenRenderer;
import io.micronaut.transaction.annotation.Transactional;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.validation.constraints.NotBlank;

import java.time.Duration;
import java.util.Optional;

@Singleton
@Transactional
public class UserService {

	/** the number of seconds a user has to add a passkey after they are sent a passkey reset email */
	private static final int PASSKEY_ADDITION_EXPIRATION_SECONDS = Long.valueOf(Duration.ofMinutes(10L).toSeconds()).intValue();

	@Inject
	private ApplicationConfigurationProperties appProps;

	@Inject
	private UserRepository userRepo;

	@Inject
	private TokenGenerator tokenGenerator;

	@Inject
	private TokenRenderer tokenRenderer;

	@Inject
	private MailTemplateService mailTemplateService;

	public String generateConfirmationJwt(User user, ConfirmationRequest confReq) {
		return generateSignedJwtForConfirmationRequest(user, confReq)
				.map(AccessRefreshToken::getAccessToken)
				.orElseThrow(() -> new RuntimeException("Unable to generate a confirmation token"));
	}

	public Optional<AccessRefreshToken> generateSignedJwtForConfirmationRequest(
			User user, ConfirmationRequest confReq
	) {
		ServerAuthentication authForConfirmationReq = TokenUtil.buildAuthenticationForConfirmationRequest(user, confReq);
		// This is similar to DefaultAccessRefreshTokenGenerator without an event publisher, and custom expiration
		return tokenGenerator.generateToken(authForConfirmationReq, confReq.getExpirationSeconds())
				.map(accessToken -> tokenRenderer.render(authForConfirmationReq, confReq.getExpirationSeconds(), accessToken, null));
	}

	/**
	 * @param addPasskeyUriPathWithoutToken the path in the web app URL to add a passkey, such as "/login/addPasskeyViaToken"
	 */
	public PasskeyAdditionLinkEmailTemplate generatePasskeyAdditionLinkEmailTemplate(
			@NonNull @NotBlank String addPasskeyUriPathWithoutToken, User user
	) {
		ConfirmationRequest confReq = ConfirmationRequest.builder()
				.type(ConfirmationType.PASSKEY_ADDITION)
				.email(user.getEmail())
				.expirationSeconds(PASSKEY_ADDITION_EXPIRATION_SECONDS)
				.build();
		String confirmationToken = generateConfirmationJwt(user, confReq);
		Contact contact = new Contact(user.getEmail(), user.getName());

		return buildPasskeyAdditionLinkEmailTemplate(addPasskeyUriPathWithoutToken, confirmationToken, contact, confReq.getExpirationSeconds().intValue() / 60);
	}

	/**
	 * @param addPasskeyUriPathWithoutToken the path in the web app URL to add a passkey, such as "/login/addPasskeyViaToken"
	 */
	public PasskeyAdditionLinkEmailTemplate buildPasskeyAdditionLinkEmailTemplate(
			@NonNull @NotBlank String addPasskeyUriPathWithoutToken,
			String confirmationToken, Contact contact, int tokenExpirationMinutes
	) {
		return PasskeyAdditionLinkEmailTemplate.builder()
				.recipient(contact)
				// Not a template view because the passkey must be added from the web app
				.webPasskeyAdditionUrl(UriBuilder.of(appProps.getWebAppUrl() + addPasskeyUriPathWithoutToken)
						.queryParam("token", confirmationToken)
						// Include the email for display purposes
						.queryParam("email", contact.getEmail())
						.toString()
				)
				.tokenExpirationMinutes(tokenExpirationMinutes)
				.build();
	}

	/**
	 * @param addPasskeyUriPathWithoutToken the path in the web app URL to add a passkey, such as "/login/addPasskeyViaToken"
	 * @return true if the email was sent, or false if it was not, such as if the user doesn't exist.
	 */
	public boolean sendPasskeyAdditionLinkEmail(
			@NonNull @NotBlank String addPasskeyUriPathWithoutToken, @NonNull @NotBlank String email
	) {
		email = EmailUtil.formatEmailAddress(email);
		User user = email == null ? null : userRepo.findByEmail(email).orElse(null);

		boolean sent = false;
		if (user != null && user.isEnabled()) {
			PasskeyAdditionLinkEmailTemplate template = generatePasskeyAdditionLinkEmailTemplate(addPasskeyUriPathWithoutToken, user);

			mailTemplateService.sendPasskeyAdditionLinkEmail(template);
			sent = true;
		}
		return sent;
	}
}
