package io.github.baylorpaul.webauthn4jmicronaut.service.mail;

import io.micronaut.context.annotation.Primary;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.email.Email;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Assertions;

import java.util.ArrayList;
import java.util.List;

@Primary
@Requires(property = "test.special.email-service", value = "mock")
@Singleton
public class MockEmailService implements EmailService {

	public record EmailContent(
			@NonNull Email email,
			@Nullable Object serializableContent
	) {}

	public List<EmailContent> emailContents = new ArrayList<>();

	@Override
	public void send(
			@NonNull Email.Builder email,
			@Nullable Object serializableContent
	) {
		EmailContent content = new EmailContent(email.build(), serializableContent);
		emailContents.add(content);
	}

	public void clearEmailContents() {
		emailContents.clear();
	}

	public @Nullable EmailContent getLastEmailContent() {
		return emailContents.isEmpty() ? null : emailContents.getLast();
	}

	public @Nullable Object assertAndReadLastEmailSerializableContent() {
		MockEmailService.EmailContent emailContent = getLastEmailContent();
		Assertions.assertNotNull(emailContent);
		Object serializableContent = emailContent.serializableContent();
		Assertions.assertNotNull(serializableContent);
		return serializableContent;
	}

	public @NonNull <T> T assertAndReadLastEmailContentValue(Class<T> clazz) {
		Object value = assertAndReadLastEmailSerializableContent();
		if (clazz.isAssignableFrom(value.getClass())) {
			return (T) value;
		} else {
			throw new UnsupportedOperationException("expected class " + clazz.getSimpleName() + ", got " + value.getClass().getName());
		}
	}
}
