package io.github.baylorpaul.webauthn4jmicronaut;

import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.authenticator.*;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.jws.JWSHeader;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.serialization.JsonIncludeAlwaysMixin;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.serialization.PasskeyEntityByteArrayIdMixin;
import io.micronaut.serde.annotation.SerdeImport;

@SerdeImport.Repeated({
		// PasskeyEntityByteArrayIdMixin - Serialize the byte array ID to a Base64Url string, instead of a JSON number[]
		@SerdeImport(value = PublicKeyCredentialDescriptor.class, mixin = PasskeyEntityByteArrayIdMixin.class),
		@SerdeImport(value = PublicKeyCredentialUserEntity.class, mixin = PasskeyEntityByteArrayIdMixin.class),

		// JsonIncludeAlwaysMixin - fix an issue with Micronaut Serialization where one of the members is null, and its
		// implementing class uses @JsonValue on one of its fields. This mixin is not necessarily needed if the member
		// is a nullable Collection of such an instance, such as `@Nullable Set<AuthenticatorTransport> transports`
		//@SerdeImport(value = AbstractCOSEKey.class, mixin = JsonIncludeAlwaysMixin.class),
		@SerdeImport(value = AuthenticatorAttestationResponse.class, mixin = JsonIncludeAlwaysMixin.class),
		@SerdeImport(value = AuthenticatorSelectionCriteria.class, mixin = JsonIncludeAlwaysMixin.class),
		//@SerdeImport(value = COSEKey.class, mixin = JsonIncludeAlwaysMixin.class),
		@SerdeImport(value = EC2COSEKey.class, mixin = JsonIncludeAlwaysMixin.class),
		@SerdeImport(value = EdDSACOSEKey.class, mixin = JsonIncludeAlwaysMixin.class),
		@SerdeImport(value = JWSHeader.class, mixin = JsonIncludeAlwaysMixin.class),
		@SerdeImport(value = PublicKeyCredential.class, mixin = JsonIncludeAlwaysMixin.class),
		@SerdeImport(value = PublicKeyCredentialCreationOptions.class, mixin = JsonIncludeAlwaysMixin.class),
		@SerdeImport(value = PublicKeyCredentialRequestOptions.class, mixin = JsonIncludeAlwaysMixin.class),
		@SerdeImport(value = RSACOSEKey.class, mixin = JsonIncludeAlwaysMixin.class),

		// No mixin
		@SerdeImport(AttestationConveyancePreference.class),
		@SerdeImport(AuthenticationExtensionsClientInputs.class),
		@SerdeImport(AuthenticationExtensionsClientOutputs.class),
		@SerdeImport(AuthenticatorAttachment.class),
		@SerdeImport(AuthenticatorTransport.class),
		@SerdeImport(COSEAlgorithmIdentifier.class),
		@SerdeImport(DefaultChallenge.class),
		@SerdeImport(PublicKeyCredentialHints.class),
		@SerdeImport(PublicKeyCredentialParameters.class),
		@SerdeImport(PublicKeyCredentialRpEntity.class),
		@SerdeImport(PublicKeyCredentialType.class),
		@SerdeImport(ResidentKeyRequirement.class),
		@SerdeImport(UserVerificationRequirement.class)
})
public class WebAuthn4jSerdeConfig {
}
