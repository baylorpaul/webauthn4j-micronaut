package io.github.baylorpaul.webauthn4jmicronaut.util;

import jakarta.annotation.Nullable;

import java.util.regex.Pattern;

public class EmailUtil {

	/**
	 * @see <a href="https://www.baeldung.com/java-email-validation-regex">Email Validation in Java</a>
	 */
	private static final String EMAIL_REGEX = "^(?=.{1,64}@)[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)*@[^-][A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)*(\\.[A-Za-z]{2,})$";
	private static final Pattern EMAIL_PATTERN = Pattern.compile(EMAIL_REGEX);

	public static @Nullable String formatEmailAddress(@Nullable String emailAddress) {
		emailAddress = emailAddress == null ? "" : emailAddress.trim().toLowerCase();
		if (emailAddress.trim().isEmpty() || !EmailUtil.isValidEmail(emailAddress)) {
			return null;
		} else {
			return emailAddress;
		}
	}

	public static boolean isValidEmail(String email) {
		return EMAIL_PATTERN.matcher(email).matches();
	}
}
