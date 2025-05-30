package io.github.baylorpaul.webauthn4jmicronaut.util;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.exceptions.HttpStatusException;
import jakarta.annotation.Nullable;

import java.util.function.Consumer;

public class ApiUtil {

	private static final int MAX_LENGTH_EMAIL = 256;
	private static final int MAX_LENGTH_NAME = 256;

	public static void validateEmail(@NonNull String email) throws HttpStatusException {
		if (!EmailUtil.isValidEmail(email)) {
			throw new HttpStatusException(HttpStatus.BAD_REQUEST, "Invalid 'email' address");
		} else if (email.length() > MAX_LENGTH_EMAIL) {
			throw new HttpStatusException(HttpStatus.BAD_REQUEST, "The 'email' address is too long [max: " + MAX_LENGTH_EMAIL + "]");
		}
	}

	public static @NonNull String formatAndValidateEmail(@Nullable String email) throws HttpStatusException {
		String formattedEmail = EmailUtil.formatEmailAddress(email);
		if (Utility.isEmptyTrimmed(formattedEmail)) {
			throw new HttpStatusException(HttpStatus.BAD_REQUEST, "A valid email address is required");
		}
		validateEmail(formattedEmail);
		return formattedEmail;
	}

	public static String buildAndValidateUserName(String name, @NonNull String email) throws HttpStatusException {
		String result = Utility.isEmptyTrimmed(name)
				? email.substring(0, email.indexOf('@'))
				: name.trim();

		if (result.length() > MAX_LENGTH_NAME) {
			throw new HttpStatusException(HttpStatus.BAD_REQUEST, "The user 'name' is too long [max: " + MAX_LENGTH_NAME + "]");
		}
		return result;
	}

	public static void setNonEmptyStr(String fieldName, String value, Consumer<String> setter) {
		if (Utility.isEmptyTrimmed(value)) {
			throw new HttpStatusException(HttpStatus.BAD_REQUEST, fieldName + " is required");
		}
		setter.accept(value);
	}
}
