/*
 * Copyright 2017-2024 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.github.baylorpaul.webauthn4jmicronaut.security.validator;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import io.github.baylorpaul.webauthn4jmicronaut.security.TokenUtil;
import io.github.baylorpaul.webauthn4jmicronaut.util.Utility;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.Claims;
import io.micronaut.security.token.jwt.generator.claims.JwtClaimsSetAdapter;
import io.micronaut.security.token.jwt.signature.ReactiveSignatureConfiguration;
import io.micronaut.security.token.jwt.signature.SignatureConfiguration;
import io.micronaut.security.token.jwt.validator.*;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

/**
 * Similar to NimbusJsonWebTokenValidator for access/authorization JWTs, but here we validate a confirmation JWT (e.g.
 * not an access/authorization JWT).
 * We are specifically not implementing io.micronaut.security.token.validator.TokenValidator, as we do not want to use
 * this validator for access/authorization JWTs.
 *
 * @param <R> Request
 */
@Singleton
public class ConfirmationJsonWebTokenValidator<R> implements JsonWebTokenValidator<JWT, R> {
	private final boolean noSignatures;
	private final List<? extends JwtClaimsValidator<R>> claimsValidators;
	private final JsonWebTokenParser<JWT> jsonWebTokenParser;
	private final JsonWebTokenSignatureValidator<SignedJWT> signatureValidator;
	private final JwtAuthenticationFactory jwtAuthenticationFactory;

	/**
	 * @param genericJwtClaimsValidators Generic JWT Claims validators which should be used to validate any JWT.
	 * @param imperativeSignatureConfigurations  List of Signature configurations which are used to attempt validation.
	 * @param reactiveSignatureConfigurations Reactive Signature Configuration.
	 * @param jsonWebTokenParser JSON Web Token (JWT) parser.
	 * @param signatureValidator API to validate the signature of a JSON Web Token
	 * @param jwtAuthenticationFactory  Utility to generate an Authentication given a JWT.
	 */
	@Inject
	public ConfirmationJsonWebTokenValidator(
			List<GenericJwtClaimsValidator<R>> genericJwtClaimsValidators,
			List<SignatureConfiguration> imperativeSignatureConfigurations,
			List<ReactiveSignatureConfiguration<SignedJWT>> reactiveSignatureConfigurations,
			JsonWebTokenParser<JWT> jsonWebTokenParser,
			JsonWebTokenSignatureValidator<SignedJWT> signatureValidator,
			JwtAuthenticationFactory jwtAuthenticationFactory
	) {
		List<GenericJwtClaimsValidator<R>> filteredJwtClaimsValidators = adjustClaimsValidatorsForConfirmationJwt(genericJwtClaimsValidators);

		this.claimsValidators = filteredJwtClaimsValidators;
		this.noSignatures = imperativeSignatureConfigurations.isEmpty() && reactiveSignatureConfigurations.isEmpty();
		this.jsonWebTokenParser = jsonWebTokenParser;
		this.signatureValidator = signatureValidator;
		this.jwtAuthenticationFactory = jwtAuthenticationFactory;
	}

	private static final class ConfirmationTypeValidator<T> implements GenericJwtClaimsValidator<T> {
		@Override
		public boolean validate(@NonNull Claims claims, @Nullable T request) {
			JWTClaimsSet claimsSet = JWTClaimsSetUtils.jwtClaimsSetFromClaims(claims);

			String confirmationTypeStr = null;
			try {
				confirmationTypeStr = claimsSet.getStringClaim(TokenUtil.CLAIM_NAME_CONFIRMATION_TYPE);
			} catch (ParseException e) {
				// do nothing - unexpected value
			}

			// We just need any value for a confirmation type
			return !Utility.isEmptyTrimmed(confirmationTypeStr);
		}
	}

	/**
	 * Use the same JWT claim validators as for access/authorization JWT.
	 * And add a validator for ensuring there is a confirmation type.
	 */
	private static <R> List<GenericJwtClaimsValidator<R>> adjustClaimsValidatorsForConfirmationJwt(
			Collection<GenericJwtClaimsValidator<R>> genericJwtClaimsValidators
	) {
		List<GenericJwtClaimsValidator<R>> l = new ArrayList<>(genericJwtClaimsValidators);

		// Add a validator just for confirmation tokens (not access/authorization JWTs)
		l.add(new ConfirmationTypeValidator<>());

		return l;
	}

	protected boolean validateClaims(JWT jwt, R request) {
		if (claimsValidators.isEmpty()) {
			return true;
		}
		try {
			Claims claims = new JwtClaimsSetAdapter(jwt.getJWTClaimsSet());
			if (claimsValidators.stream().allMatch(validator -> validator.validate(claims, request))) {
				return true;
			}
		} catch (ParseException e) {
			// Failed to retrieve the claims set
		}
		return false;
	}

	@NonNull
	@Override
	public Optional<JWT> validate(@NonNull String token, @Nullable R request) {
		Optional<JWT> jwtOptional = jsonWebTokenParser.parse(token);
		if (jwtOptional.isEmpty()) {
			return Optional.empty();
		}
		JWT jwt = jwtOptional.get();
		if (!validateSignature(jwt)) {
			return Optional.empty();
		}
		if (!validateClaims(jwt, request)) {
			return Optional.empty();
		}
		return Optional.of(jwt);
	}

	/***
	 * @param token The token string.
	 * @return Publishes {@link Authentication} based on the JWT or empty if the validation fails.
	 */
	public Optional<Authentication> validateToken(String token, @Nullable R request) {
		return validate(token, request)
				.flatMap(jwtAuthenticationFactory::createAuthentication);
	}

	private boolean validateSignature(JWT jwt) {
		if (jwt instanceof PlainJWT) {
			return noSignatures;
		} else if (jwt instanceof SignedJWT signedJWT) {
			return signatureValidator.validateSignature(signedJWT);
		}
		return false;
	}
}
