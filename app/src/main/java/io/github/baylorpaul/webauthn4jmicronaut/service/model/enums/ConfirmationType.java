package io.github.baylorpaul.webauthn4jmicronaut.service.model.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum ConfirmationType {
	/** For emailing a link to add a passkey to a user's account */
	PASSKEY_ADDITION(false),
	/**
	 * Some actions require the user to re-authenticate to confirm their identity. The user may confirm access via
	 * password entry, re-verifying their federated login, or via passkey. This type is for passkey verification. When
	 * the user re-authenticates via passkey, a confirmation token of this type is issued, and that token shall be
	 * submitted with the action. E.g. if the user is adding an integration token, changing their password, or adding
	 * another passkey to their account.
	 */
	PASSKEY_ACCESS_VERIFIED(false),
	;

	/** true if the token may be used more than once, or false if it becomes invalid after one use */
	private final boolean tokenReusePermitted;
}
