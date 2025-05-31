package io.github.baylorpaul.webauthn4jmicronaut.service.mail;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.email.Email;

public interface EmailService {
	/**
	 * Send an email
	 * @param email the email content to send
	 * @param serializableContent a simplified version of the email content that may be persisted, such as in JSON. E.g. {"type": "EMAIL_VERIFICATION", "recipient": "joe@example.com"}
	 */
	void send(
			@NonNull Email.Builder email,
			@Nullable Object serializableContent
	);
}
