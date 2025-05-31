package io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.serialization;

import com.webauthn4j.util.Base64UrlUtil;
import io.micronaut.context.annotation.Secondary;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.type.Argument;
import io.micronaut.serde.Decoder;
import io.micronaut.serde.Encoder;
import io.micronaut.serde.Serde;
import jakarta.inject.Singleton;

import java.io.IOException;

/**
 * Serialize/deserialize a byte array in Base64Url encoding
 * Using {@link Secondary} so that Base64Url encoding is not chosen as the default serialization method. Use this by
 * specifying e.g. @Serdeable.Serializable.using/@Serdeable.Deserializable.using or @SerdeImport.mixin.
 */
@Singleton
@Secondary
public class ByteArrayBase64UrlSerde implements Serde<byte[]> {

	@Override
	public void serialize(
			@NonNull Encoder encoder, @NonNull EncoderContext context,
			@NonNull Argument<? extends byte[]> type,
			@NonNull byte[] value
	) throws IOException {
		String str = Base64UrlUtil.encodeToString(value);
		encoder.encodeString(str);
	}

	@Override
	public byte @Nullable [] deserialize(
			@NonNull Decoder decoder, @NonNull DecoderContext context, @NonNull Argument<? super byte[]> type
	) throws IOException {
		String base64UrlEncoding = decoder.decodeString();
		return Base64UrlUtil.decode(base64UrlEncoding);
	}
}
