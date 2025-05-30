package io.github.baylorpaul.webauthn4jmicronaut.service.mail;

import io.github.baylorpaul.webauthn4jmicronaut.service.mail.template.GenericTemplate;
import io.github.baylorpaul.webauthn4jmicronaut.service.mail.template.PasskeyAdditionLinkEmailTemplate;
import io.github.baylorpaul.webauthn4jmicronaut.util.Utility;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Singleton
public class MailTemplateService {
	private static final Logger log = LoggerFactory.getLogger(MailTemplateService.class);

	private void sendEmail(
			String emailDescription, GenericTemplate template, String logContent
	) {
		// TODO this app doesn't send live emails. Please implement that yourself if you need it.

		// Log some info since some necessary fields may be marked @JsonIgnore, and we're not going to send an email
		log.info(emailDescription + " details since live email is disabled --> [email="
				+ template.getRecipient().getEmail() + (Utility.isEmptyTrimmed(logContent) ? "" : ", " + logContent) + "]");
	}

	public void sendPasskeyAdditionLinkEmail(PasskeyAdditionLinkEmailTemplate template) {
		sendEmail(
				"Passkey addition link",
				template,
				"webPasskeyAdditionUrl=" + template.getWebPasskeyAdditionUrl()
		);
	}
}
