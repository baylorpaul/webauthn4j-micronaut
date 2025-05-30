package io.github.baylorpaul.webauthn4jmicronaut.util;

import io.github.baylorpaul.webauthn4jmicronaut.entity.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PasswordUtil {
	private static final Logger log = LoggerFactory.getLogger(PasswordUtil.class);

	public static final String FAKE_PASSWORD = "topsecret";

	public static boolean passwordMatches(String rawPassword, User user) {

		log.error("WARNING!!! NO SECURITY for password matching! We're just looking for the hardcoded constant value. Please implement a password matcher!");

		// TODO check that the "rawPassword" matches the user's password.
		return FAKE_PASSWORD.equals(rawPassword);
	}
}
