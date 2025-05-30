package io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.serialization;

import io.micronaut.serde.annotation.Serdeable;

/**
 * Serialize a PublicKeyCredentialDescriptor or PublicKeyCredentialUserEntity, mapping the byte array ID to a Base64Url
 * string. Otherwise, the byte[] will serialize as a JSON number[], which the client will need to parse into a
 * Uint8Array, and then likely to a Base64Url. This does the conversion before the client receives the data.
 * @see <a href="https://simplewebauthn.dev/docs/packages/browser#buffertobase64urlstring">bufferToBase64URLString()</a>
 */
public interface PasskeyEntityByteArrayIdMixin {
	@Serdeable.Serializable(using = ByteArrayBase64UrlSerializer.class)
	byte[] getId();
}
