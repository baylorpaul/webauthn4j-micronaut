package io.github.baylorpaul.webauthn4jmicronaut.service.mail;

import io.github.baylorpaul.webauthn4jmicronaut.service.JsonService;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.email.Email;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Singleton
public class CustomMailService implements EmailService {
	private static final Logger log = LoggerFactory.getLogger(CustomMailService.class);

	@Inject
	private JsonService jsonService;

	@Override
	public void send(
			@NonNull Email.Builder email,
			@Nullable Object serializableContent
	) {
		// TODO this app doesn't send live emails. Please implement that yourself if you need it.

		log.info("Live email not implemented. Message skipped: " + jsonService.toJson(serializableContent));
	}
}
