package io.github.baylorpaul.webauthn4jmicronaut.security.model;

import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.Getter;

import java.util.List;

/**
 * Passkey/WebAuthn credential information to be persisted and read from persistent storage
 */
@Getter
@Builder
public class PasskeyCredentialsPersistable {
	/** The Base64Url encoded Passkey/WebAuthn credential ID. This also exists in the "attestedCredentialData" */
	private @NotBlank String base64UrlCredentialId;
	/**
	 * The attested credential data (aaguid, credentialId, credentialPublicKey) as a byte array.
	 * The "aaguid" identifies the model of the authenticator (not the specific instance of the authenticator).
	 * The "credentialPublicKey" is written to the byte array via CBOR (Concise Binary Object Representation) encoding.
	 * No encryption is required, as this is a public key, and the server never has access to the private key.
	 * @see <a href="https://www.w3.org/TR/webauthn-1/#sec-attested-credential-data">Attested Credential Data</a>
	 */
	private @NotNull byte[] attestedCredentialDataBytes;
	/**
	 * The attestation statement envelope, encoded in CBOR (Concise Binary Object Representation). This includes the
	 * attestation type (E.g. "direct", "indirect", "none") in the "fmt" key. It also includes the attestation statement
	 * in the "attStmt" key.
	 */
	private @NotNull byte[] attestationStatementEnvelope;
	/** the authenticator extensions supported as JSON */
	private @Nullable String authenticatorExtensionsJson;
	/** Counter to prevent replay attacks */
	private long signatureCount;
	/** Credential type. E.g. "webauthn.create", "webauthn.get" */
	private @NotNull String type;
	/** the client extensions supported as JSON */
	private @Nullable String clientExtensionsJson;
	/** the transport methods supported. E.g. ["internal","hybrid"] */
	private @Nullable List<String> transports;
	/** Indicates whether user verification was performed */
	private boolean uvInitialized;
	/** The value of the Backup Eligibility flag when the public key credential source was created */
	private boolean backupEligible;
	/** Whether the public key credential source is currently backed up */
	private boolean backupState;
}
