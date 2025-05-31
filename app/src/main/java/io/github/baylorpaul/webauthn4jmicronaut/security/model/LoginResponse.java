package io.github.baylorpaul.webauthn4jmicronaut.security.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.serde.annotation.Serdeable;
import lombok.Data;

/**
 * A BearerAccessRefreshToken that encapsulates an Access Token response as described in
 * <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.4">RFC 6749</a>.
 */
@Data
@Serdeable
public class LoginResponse {
	private @NonNull @JsonProperty("access_token") String accessToken;
	private @JsonProperty("refresh_token") String refreshToken;
	/** The token type, such as "Bearer" */
	private @JsonProperty("token_type") String tokenType;
	/** The number of seconds the access token is valid since it was issued */
	private @JsonProperty("expires_in") long expiresIn;
	private String username;
}
