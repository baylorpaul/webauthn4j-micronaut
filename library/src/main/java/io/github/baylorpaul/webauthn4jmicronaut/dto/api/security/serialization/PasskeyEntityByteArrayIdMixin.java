package io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.serialization;

import io.micronaut.serde.annotation.Serdeable;

/**
 * Serialize a PublicKeyCredentialDescriptor or PublicKeyCredentialUserEntity, mapping the byte array ID to a Base64Url
 * string. Otherwise, the byte[] will serialize as a JSON number[], which the client will need to parse into a
 * Uint8Array, and then likely to a Base64Url. This does the conversion before the client receives the data.
 * In addition to other WebAuthn class <code>{@literal @}SerdeImport</code>s that do not require a mixin, the
 * PasskeyEntityByteArrayIdMixin should be used for the following, such as on a Passkey controller class so that the
 * byte array IDs are serialized as Base64Url strings instead of a JSON number[]:
 * <pre>
 * {@literal @}SerdeImport.Repeated({
 *     {@literal @}SerdeImport(
 *          value = PublicKeyCredentialUserEntity.class,
 *          mixin = PasskeyEntityByteArrayIdMixin.class
 *      ),
 *     {@literal @}SerdeImport(
 *          value = PublicKeyCredentialDescriptor.class,
 *          mixin = PasskeyEntityByteArrayIdMixin.class
 *      )
 *  })</pre>
 * @see <a href="https://simplewebauthn.dev/docs/packages/browser#buffertobase64urlstring">bufferToBase64URLString()</a>
 */
public interface PasskeyEntityByteArrayIdMixin {
	@Serdeable.Serializable(using = ByteArrayBase64UrlSerde.class)
	@Serdeable.Deserializable(using = ByteArrayBase64UrlSerde.class)
	byte[] getId();
}
