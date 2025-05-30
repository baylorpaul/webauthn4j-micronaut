package io.github.baylorpaul.webauthn4jmicronaut.entity;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.data.annotation.*;
import io.micronaut.data.model.DataType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;

@MappedEntity
@Data
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
public class PasskeyCredentials {
	private @Id @GeneratedValue @NonNull long id;
	private @Relation(Relation.Kind.MANY_TO_ONE) User user;
	/** The Base64Url encoded Passkey/WebAuthn credential ID. This also exists in the "attestedCredentialData" */
	private @NotBlank String credentialId;

	/**
	 * The attested credential data (aaguid, credentialId, credentialPublicKey) as a byte array.
	 * The "aaguid" identifies the model of the authenticator (not the specific instance of the authenticator).
	 * The "credentialPublicKey" is written to the byte array via CBOR (Concise Binary Object Representation) encoding.
	 * No encryption is required, as this is a public key, and the server never has access to the private key.
	 * @see <a href="https://www.w3.org/TR/webauthn-1/#sec-attested-credential-data">Attested Credential Data</a>
	 */
	private @NotNull byte[] attestedCredentialData;

	/**
	 * The attestation statement envelope, encoded in CBOR (Concise Binary Object Representation). This includes the
	 * attestation type (E.g. "direct", "indirect", "none") in the "fmt" key. It also includes the attestation statement
	 * in the "attStmt" key.
	 */
	private @NotNull byte[] attestationStatementEnvelope;

	//private @NotNull AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> authenticatorExtensions;

	/** Counter to prevent replay attacks */
	private long signatureCount;
	/** Credential type. E.g. "webauthn.create", "webauthn.get" */
	private @NotNull String type;

	//private @Nullable AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions;

	/** the transport methods supported. E.g. ["internal","hybrid"] */
	private @Nullable @TypeDef(type = DataType.STRING_ARRAY) List<String> transports;
	/** Indicates whether user verification was performed */
	private boolean uvInitialized;
	/** The value of the Backup Eligibility flag when the public key credential source was created */
	private boolean backupEligible;
	/** Whether the public key credential source is currently backed up */
	private boolean backupState;
	/** Timestamp for last usage of the credential in an authentication process */
	private @Nullable Instant lastUsedDate;
	private @GeneratedValue Instant created;
	private @GeneratedValue Instant updated;
}
