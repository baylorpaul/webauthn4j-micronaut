package io.github.baylorpaul.webauthn4jmicronaut.service.model.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum ConfirmationType {
	/** For emailing a link to add a passkey to a user's account */
	PASSKEY_ADDITION(false),
	;

	/** true if the token may be used more than once, or false if it becomes invalid after one use */
	private final boolean tokenReusePermitted;
}
