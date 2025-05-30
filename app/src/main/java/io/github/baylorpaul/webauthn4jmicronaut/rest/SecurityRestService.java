package io.github.baylorpaul.webauthn4jmicronaut.rest;

import io.github.baylorpaul.webauthn4jmicronaut.entity.User;
import io.github.baylorpaul.webauthn4jmicronaut.entity.UtilizedConfirmationToken;
import io.github.baylorpaul.webauthn4jmicronaut.repo.UserRepository;
import io.github.baylorpaul.webauthn4jmicronaut.repo.UtilizedConfirmationTokenRepository;
import io.github.baylorpaul.webauthn4jmicronaut.security.SecurityUtil;
import io.github.baylorpaul.webauthn4jmicronaut.security.TokenUtil;
import io.github.baylorpaul.webauthn4jmicronaut.security.validator.ConfirmationJsonWebTokenValidator;
import io.github.baylorpaul.webauthn4jmicronaut.service.LockService;
import io.github.baylorpaul.webauthn4jmicronaut.service.SystemService;
import io.github.baylorpaul.webauthn4jmicronaut.service.model.enums.ConfirmationType;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.exceptions.HttpStatusException;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.transaction.annotation.Transactional;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.validation.constraints.NotBlank;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

@Singleton
@Transactional
public class SecurityRestService {

	@Inject
	private ConfirmationJsonWebTokenValidator<?> confirmationJsonWebTokenValidator;

	@Inject
	private UserRepository userRepo;

	@Inject
	private UtilizedConfirmationTokenRepository utilizedConfirmationTokenRepo;

	@Inject
	private SystemService systemService;

	@Inject
	private LockService lockService;

	private record UserAndExpiration(@NonNull User user, @Nullable Instant tokenExpirationDate) {}

	private @NonNull UserAndExpiration validateConfirmationTokenAndFindUser(
			@NonNull Authentication auth, @NonNull ConfirmationType expectedConfirmationType
	) throws HttpStatusException {
		Map<String, Object> claims = auth.getAttributes();
		UserAndExpiration userAndExp = findJwtUserIfNotExpired(claims);
		User user = userAndExp == null ? null : userAndExp.user();

		if (user == null) {
			throw new HttpStatusException(HttpStatus.BAD_REQUEST, "Token is expired or does not match an active user");
		} else if (!expectedConfirmationType.toString().equals(claims.get(TokenUtil.CLAIM_NAME_CONFIRMATION_TYPE))) {
			throw new HttpStatusException(HttpStatus.BAD_REQUEST, "Invalid confirmation type");
		} else if (!user.getEmail().equals(claims.get(TokenUtil.CLAIM_NAME_EMAIL))) {
			throw new HttpStatusException(HttpStatus.CONFLICT, "Email address for user does not currently match the address being verified");
		}

		return userAndExp;
	}

	/**
	 * @param subjectToTokenInvalidation true if the token should be invalidated for later use when the token
	 *            confirmation type does not allow token reuse. This may be false while gathering information before the
	 *            action is taking place.
	 */
	public @NonNull User findUserIfValidConfirmationToken(
			@NonNull @NotBlank String token, @NonNull ConfirmationType expectedConfirmationType,
			boolean subjectToTokenInvalidation
	) {
		Authentication auth = SecurityUtil.validateConfirmationJwt(confirmationJsonWebTokenValidator, token)
				.orElseThrow(() -> new HttpStatusException(HttpStatus.UNAUTHORIZED, "invalid token"));

		UserAndExpiration userAndExp = validateConfirmationTokenAndFindUser(auth, expectedConfirmationType);

		if (!expectedConfirmationType.isTokenReusePermitted()) {
			validateTokenNotPreviouslyExercised(userAndExp, token, expectedConfirmationType, subjectToTokenInvalidation);
		}

		return userAndExp.user();
	}

	/**
	 * Ensure the confirmation token was not previously exercised/utilized, and optionally invalidate the token, which
	 * means persisting the token as exercised.
	 * @param invalidateToken true to invalidate the token, so it may not be reused later
	 * @throws HttpStatusException if the token was previously exercised
	 */
	private void validateTokenNotPreviouslyExercised(
			@NonNull UserAndExpiration userAndExp, @NonNull @NotBlank String token,
			@NonNull ConfirmationType expectedConfirmationType, boolean invalidateToken
	) throws HttpStatusException {
		long userId = userAndExp.user().getId();
		// Execute the following with an advisory lock so that concurrent requests won't both succeed
		lockService.advisoryLockExclusiveTxn(LockService.AdvisoryLockType.UTILIZED_CONFIRMATION_TOKEN_USER, (int) userId);

		// See if the token has already been used. It doesn't matter if it's assigned to the same user or not.
		Optional<UtilizedConfirmationToken> utilizedTokenOpt = utilizedConfirmationTokenRepo.findByUtilizedToken(token);
		if (utilizedTokenOpt.isPresent()) {
			throw new HttpStatusException(HttpStatus.GONE, "Confirmation token has already been utilized");
		} else if (userAndExp.tokenExpirationDate() == null) {
			throw new HttpStatusException(HttpStatus.BAD_REQUEST, "Missing token expiration date");
		} else if (invalidateToken) {
			// Persist the token as exercised so that it may not be reused later
			UtilizedConfirmationToken utilizedToken = UtilizedConfirmationToken.builder()
					.user(userAndExp.user())
					.type(expectedConfirmationType)
					.utilizedToken(token)
					.expirationDate(userAndExp.tokenExpirationDate())
					.build();
			utilizedToken = utilizedConfirmationTokenRepo.save(utilizedToken);
		}
	}

	/**
	 * Find the user for the JWT, as long as the JWT is not expired, and the user is enabled
	 */
	private @Nullable UserAndExpiration findJwtUserIfNotExpired(Map<String, Object> claims) {
		UserAndExpiration result = null;
		if (claims != null) {
			Long userId = TokenUtil.findJwtSubjectAsUserId(claims);
			User matchingUser = userId == null ? null : userRepo.findById(userId).orElse(null);
			if (matchingUser != null && matchingUser.isEnabled()) {
				Instant expiration = TokenUtil.findJwtExpirationDate(claims);
				if (expiration == null || expiration.compareTo(systemService.getNow()) > 0) {
					result = new UserAndExpiration(matchingUser, expiration);
				}
			}
		}
		return result;
	}
}
