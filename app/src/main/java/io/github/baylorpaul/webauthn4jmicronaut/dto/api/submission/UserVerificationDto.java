package io.github.baylorpaul.webauthn4jmicronaut.dto.api.submission;

import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.annotation.ReflectiveAccess;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * A request that verifies user identity
 */
@Data
@Builder
@Serdeable
@NoArgsConstructor
@AllArgsConstructor
@ReflectiveAccess
public class UserVerificationDto {

	/** the platform on which we are authenticating. Expecting one of "android", "ios", or "web" */
	private @NotNull @NotBlank String platform;
	/** A short-lived JWT Confirmation Token, which was issued when passkey access was verified */
	private @Nullable String jwtPasskeyAccessVerifiedToken;
	/** A raw password, if authenticating via password */
	private @Nullable String password;
}
