package io.github.baylorpaul.webauthn4jmicronaut.security.model;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Collection;
import java.util.Map;

@Getter
@AllArgsConstructor
public class AuthenticationUserInfo {
	private @NonNull String userId;
	private boolean enabled;
	private @Nullable Collection<String> userRoles;
	/** the user attributes, such as for JWT claims */
	private @Nullable Map<String, Object> userAttributes;
}
