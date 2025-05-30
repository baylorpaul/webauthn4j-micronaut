package io.github.baylorpaul.webauthn4jmicronaut.rest;

import io.github.baylorpaul.micronautjsonapi.model.JsonApiResource;
import io.github.baylorpaul.micronautjsonapi.util.JsonApiUtil;
import io.github.baylorpaul.webauthn4jmicronaut.entity.User;
import io.github.baylorpaul.webauthn4jmicronaut.repo.UserRepository;
import io.github.baylorpaul.webauthn4jmicronaut.util.ApiUtil;
import io.github.baylorpaul.webauthn4jmicronaut.util.Utility;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.exceptions.HttpStatusException;
import io.micronaut.json.JsonMapper;
import io.micronaut.transaction.annotation.Transactional;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.validation.constraints.NotBlank;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Singleton
@Transactional
public class UserRestService {

	private static final Logger log = LoggerFactory.getLogger(UserRestService.class);

	@Inject
	private UserRepository userRepo;

	@Inject
	private JsonMapper jsonMapper;

	/**
	 * @return a non-null user that was created
	 * @throws HttpStatusException if the user cannot be created
	 */
	public User createUser(@NotBlank String email, @Nullable String name, @Nullable String encodedPassword) {
		// Ensure the email address is valid, formatted as expected, and unique
		String formattedEmail = formatEmailAndEnsureUniqueness(email, true);
		String formattedDisplayName = ApiUtil.buildAndValidateUserName(name, formattedEmail);

		User newUser = userRepo.save(
				User.builder()
						.email(formattedEmail)
						.name(formattedDisplayName)
						.enabled(true)
						.build()
		);

		log.info("Created new user [id: " + newUser.getId() + "]");

		return newUser;
	}

	/**
	 * Ensure the email address is valid, formatted as expected, and optionally check that it is not used already for another user
	 * @return the properly formatted, unique email
	 * @throws HttpStatusException if a validation error occurs or the email is not unique
	 */
	public @NonNull String formatEmailAndEnsureUniqueness(
			String email, boolean ensureUniqueness
	) throws HttpStatusException {
		String formattedEmail = ApiUtil.formatAndValidateEmail(email);

		if (ensureUniqueness && userRepo.findByEmail(formattedEmail).isPresent()) {
			throw new HttpStatusException(HttpStatus.CONFLICT, "email address already in use");
		}
		return formattedEmail;
	}

	public User updateUser(@NonNull User user, @NonNull JsonApiResource res) {
		if (res.getAttributes() != null) {
			User dto = JsonApiUtil.readValue(jsonMapper, res.getAttributes(), User.class);
			for (String key : res.getAttributes().keySet()) {
				switch (key) {
					case "name":
						String limitedName = Utility.charLimit(dto.getName(), 256, "...")
								.trim();
						ApiUtil.setNonEmptyStr(key, limitedName, user::setName);
						break;
					default:
						throw new HttpStatusException(HttpStatus.BAD_REQUEST, "Unexpected field: " + key);
				}
			}
			user = userRepo.update(user);
		}
		if (res.getRelationships() != null) {
			throw new HttpStatusException(HttpStatus.FORBIDDEN, "Relationship updates not supported for this record");
		}
		return user;
	}
}
