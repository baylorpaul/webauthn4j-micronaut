package io.github.baylorpaul.webauthn4jmicronaut;

import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.authenticator.*;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.jws.JWSHeader;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.serialization.GenericWebAuthn4JSerde;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.serialization.PasskeyEntityByteArrayIdMixin;
import io.micronaut.context.annotation.Bean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.serde.annotation.SerdeImport;

@SerdeImport.Repeated({
		// PasskeyEntityByteArrayIdMixin - Serialize the byte array ID to a Base64Url string, instead of a JSON number[]
		@SerdeImport(value = PublicKeyCredentialDescriptor.class, mixin = PasskeyEntityByteArrayIdMixin.class),
		@SerdeImport(value = PublicKeyCredentialUserEntity.class, mixin = PasskeyEntityByteArrayIdMixin.class),

		// No mixin
		@SerdeImport(AttestationConveyancePreference.class),
		@SerdeImport(AuthenticationExtensionsClientInputs.class),
		@SerdeImport(AuthenticationExtensionsClientOutputs.class),
		@SerdeImport(AuthenticatorAttachment.class),
		@SerdeImport(AuthenticatorAttestationResponse.class),
		@SerdeImport(AuthenticatorSelectionCriteria.class),
		@SerdeImport(AuthenticatorTransport.class),
		@SerdeImport(COSEAlgorithmIdentifier.class),
		@SerdeImport(DefaultChallenge.class),
		@SerdeImport(EC2COSEKey.class),
		@SerdeImport(EdDSACOSEKey.class),
		@SerdeImport(JWSHeader.class),
		@SerdeImport(PublicKeyCredential.class),
		@SerdeImport(PublicKeyCredentialCreationOptions.class),
		@SerdeImport(PublicKeyCredentialHints.class),
		@SerdeImport(PublicKeyCredentialParameters.class),
		@SerdeImport(PublicKeyCredentialRequestOptions.class),
		@SerdeImport(PublicKeyCredentialRpEntity.class),
		@SerdeImport(PublicKeyCredentialType.class),
		@SerdeImport(ResidentKeyRequirement.class),
		@SerdeImport(RSACOSEKey.class),
		@SerdeImport(UserVerificationRequirement.class)
})
@Factory
public class WebAuthn4jSerdeConfig {

	// Use Jackson serialization for the classes below to avoid a Micronaut Serialization issue with null values where
	// the class uses @JsonValue. The wrapping class needs to use such serialization, not the class with the @JsonValue.
	// Such a "Serde" is not necessarily needed if the member is a nullable Collection of one of these instances, such
	// as `@Nullable Set<AuthenticatorTransport> transports`

	@Bean
	public GenericWebAuthn4JSerde<AuthenticatorAttestationResponse> authenticatorAttestationResponseSerde() {
		return new GenericWebAuthn4JSerde<>(AuthenticatorAttestationResponse.class);
	}
	@Bean
	public GenericWebAuthn4JSerde<AuthenticatorSelectionCriteria> authenticatorSelectionCriteriaSerde() {
		return new GenericWebAuthn4JSerde<>(AuthenticatorSelectionCriteria.class);
	}
	@Bean
	public GenericWebAuthn4JSerde<EC2COSEKey> ec2COSEKeySerde() {
		return new GenericWebAuthn4JSerde<>(EC2COSEKey.class);
	}
	@Bean
	public GenericWebAuthn4JSerde<EdDSACOSEKey> edDSACOSEKeySerde() {
		return new GenericWebAuthn4JSerde<>(EdDSACOSEKey.class);
	}
	@Bean
	public GenericWebAuthn4JSerde<JWSHeader> jwsHeaderSerde() {
		return new GenericWebAuthn4JSerde<>(JWSHeader.class);
	}
	@Bean
	public GenericWebAuthn4JSerde<PublicKeyCredential> publicKeyCredentialSerde() {
		return new GenericWebAuthn4JSerde<>(PublicKeyCredential.class);
	}
	@Bean
	public GenericWebAuthn4JSerde<PublicKeyCredentialCreationOptions> publicKeyCredentialCreationOptionsSerde() {
		return new GenericWebAuthn4JSerde<>(PublicKeyCredentialCreationOptions.class);
	}
	@Bean
	public GenericWebAuthn4JSerde<PublicKeyCredentialRequestOptions> publicKeyCredentialRequestOptionsSerde() {
		return new GenericWebAuthn4JSerde<>(PublicKeyCredentialRequestOptions.class);
	}
	@Bean
	public GenericWebAuthn4JSerde<RSACOSEKey> rsaCOSEKeySerde() {
		return new GenericWebAuthn4JSerde<>(RSACOSEKey.class);
	}
}
