package io.github.baylorpaul.webauthn4jmicronaut.service.mail.template;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.ReflectiveAccess;
import io.micronaut.email.Contact;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.validation.constraints.NotBlank;
import lombok.Builder;
import lombok.Getter;

@Getter
@Serdeable
@ReflectiveAccess
public class PasskeyAdditionLinkEmailTemplate extends GenericTemplate {
	private final String type = "PASSKEY_ADDITION_LINK";
	/**
	 * the GET URL, including the token, to visit in a web page where the user may add a new passkey.
	 * This page is expected to know the API confirmation URL to call to do the actual confirmation.
	 */
	private final @JsonIgnore @NonNull @NotBlank String webPasskeyAdditionUrl;
	/** the number of minutes before the token expires */
	private final int tokenExpirationMinutes;

	@Builder
	public PasskeyAdditionLinkEmailTemplate(
			@NonNull Contact recipient,
			@NonNull @NotBlank String webPasskeyAdditionUrl,
			int tokenExpirationMinutes
	) {
		super(recipient);
		this.webPasskeyAdditionUrl = webPasskeyAdditionUrl;
		this.tokenExpirationMinutes = tokenExpirationMinutes;
	}
}
