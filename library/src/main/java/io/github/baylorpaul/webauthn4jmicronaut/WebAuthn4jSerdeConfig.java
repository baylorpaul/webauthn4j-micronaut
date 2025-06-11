package io.github.baylorpaul.webauthn4jmicronaut;

import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.serialization.JsonIncludeAlwaysMixin;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.serialization.PasskeyEntityByteArrayIdMixin;
import io.micronaut.serde.annotation.SerdeImport;

@SerdeImport.Repeated({
		@SerdeImport(PublicKeyCredentialCreationOptions.class),
		@SerdeImport(PublicKeyCredentialRpEntity.class),
		@SerdeImport(
				value = PublicKeyCredentialUserEntity.class,
				// Serialize the byte array ID to a Base64Url string, instead of a JSON number[]
				mixin = PasskeyEntityByteArrayIdMixin.class
		),
		@SerdeImport(
				value = PublicKeyCredentialDescriptor.class,
				// Serialize the byte array ID to a Base64Url string, instead of a JSON number[]
				mixin = PasskeyEntityByteArrayIdMixin.class
		),
		@SerdeImport(DefaultChallenge.class),
		@SerdeImport(PublicKeyCredentialParameters.class),
		@SerdeImport(PublicKeyCredentialType.class),
		@SerdeImport(COSEAlgorithmIdentifier.class),
		@SerdeImport(
				value = AuthenticatorSelectionCriteria.class,
// TODO apply this mixin to more wrapping classes where the object may be null, and the class has a @JsonValue
				mixin = JsonIncludeAlwaysMixin.class
		),
		@SerdeImport(PublicKeyCredentialHints.class),
		@SerdeImport(AuthenticatorAttachment.class),
		@SerdeImport(AuthenticatorTransport.class),
		@SerdeImport(AuthenticationExtensionsClientInputs.class),
		@SerdeImport(AuthenticationExtensionsClientOutputs.class),
		@SerdeImport(ResidentKeyRequirement.class),
		@SerdeImport(UserVerificationRequirement.class),
		@SerdeImport(AttestationConveyancePreference.class),
		@SerdeImport(PublicKeyCredentialRequestOptions.class)
})
public class WebAuthn4jSerdeConfig {
}
