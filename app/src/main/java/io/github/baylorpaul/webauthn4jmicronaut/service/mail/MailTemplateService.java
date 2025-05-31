package io.github.baylorpaul.webauthn4jmicronaut.service.mail;

import io.github.baylorpaul.webauthn4jmicronaut.service.mail.template.GenericTemplate;
import io.github.baylorpaul.webauthn4jmicronaut.service.mail.template.PasskeyAdditionLinkEmailTemplate;
import io.github.baylorpaul.webauthn4jmicronaut.util.Utility;
import io.micronaut.email.Email;
import io.micronaut.email.StringBody;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Singleton
public class MailTemplateService {
	private static final Logger log = LoggerFactory.getLogger(MailTemplateService.class);

	@Inject
	private EmailService emailService;

	private void sendEmail(
			String emailDescription, Email.Builder email, GenericTemplate template, String logContent
	) {
		// TODO this app doesn't send live emails. Please implement that yourself if you need it.

		// Log some info since some necessary fields may be marked @JsonIgnore, and we're not going to send an email
		log.info(emailDescription + " details since live email is disabled --> [email="
				+ template.getRecipient().getEmail() + (Utility.isEmptyTrimmed(logContent) ? "" : ", " + logContent) + "]");

		emailService.send(email, template);
	}

	protected Email.Builder buildEmailContentForPasskeyAdditionLink(PasskeyAdditionLinkEmailTemplate template) {
		return Email.builder()
				.to(template.getRecipient())
				.subject("Passkey Addition Request")
				.body(new StringBody(
						"Hi " + template.getRecipient().getName() + ",\n\n"
								+ "Please add a passkey here --> " + template.getWebPasskeyAdditionUrl()
								+ "\n\nYour reset token expires in " + template.getTokenExpirationMinutes() + " minutes."
				));
	}

	public void sendPasskeyAdditionLinkEmail(PasskeyAdditionLinkEmailTemplate template) {
		Email.Builder email = buildEmailContentForPasskeyAdditionLink(template);

		sendEmail(
				"Passkey addition link",
				email,
				template,
				"webPasskeyAdditionUrl=" + template.getWebPasskeyAdditionUrl()
		);
	}
}
