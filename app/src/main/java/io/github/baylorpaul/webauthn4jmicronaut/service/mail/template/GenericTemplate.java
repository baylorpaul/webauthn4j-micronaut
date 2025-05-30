package io.github.baylorpaul.webauthn4jmicronaut.service.mail.template;

import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.annotation.ReflectiveAccess;
import io.micronaut.email.Contact;
import io.micronaut.serde.annotation.Serdeable;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@Serdeable
@AllArgsConstructor
@ReflectiveAccess
public class GenericTemplate {
	/** the recipient */
	private final @Nullable Contact recipient;
}
