package io.github.baylorpaul.webauthn4jmicronaut.security.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import io.micronaut.core.annotation.ReflectiveAccess;
import lombok.Getter;

/**
 * A class for serializing and deserializing the attestation type and attestation statement.
 * @see <a href="https://webauthn4j.github.io/webauthn4j/en/#attestationstatement">attestationStatement</a>
 */
@Getter
@ReflectiveAccess
public class AttestationStatementEnvelope {

	@JsonProperty("attStmt")
	@JsonTypeInfo(
			use = JsonTypeInfo.Id.NAME,
			include = JsonTypeInfo.As.EXTERNAL_PROPERTY,
			property = "fmt"
	)
	private AttestationStatement attestationStatement;

	@JsonCreator
	public AttestationStatementEnvelope(@JsonProperty("attStmt") AttestationStatement attestationStatement) {
		this.attestationStatement = attestationStatement;
	}

	@JsonProperty("fmt")
	public String getFormat() {
		return attestationStatement.getFormat();
	}
}
