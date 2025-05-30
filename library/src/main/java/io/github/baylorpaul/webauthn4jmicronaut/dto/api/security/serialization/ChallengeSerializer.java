package io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.serialization;

import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.util.Base64UrlUtil;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.type.Argument;
import io.micronaut.serde.Encoder;
import io.micronaut.serde.Serializer;
import jakarta.inject.Singleton;

import java.io.IOException;

/**
 * Serialize the Challenge as a String, mapping the byte array ID to a Base64Url string.
 * Otherwise, the byte[] will serialize as a JSON number[], which the client will need to parse into a Uint8Array, and
 * then likely to a Base64Url. This does the conversion before the client receives the data.
 * @see <a href="https://simplewebauthn.dev/docs/packages/browser#buffertobase64urlstring">bufferToBase64URLString()</a>
 */
@Singleton
public class ChallengeSerializer implements Serializer<Challenge> {

	@Override
	public void serialize(
			@NonNull Encoder encoder, @NonNull EncoderContext context,
			@NonNull Argument<? extends Challenge> type,
			@NonNull Challenge challenge
	) throws IOException {
		// Change the structure. We won't have an inner "value" member. We'll just return the Base64Url string.
		String str = Base64UrlUtil.encodeToString(challenge.getValue());
		encoder.encodeString(str);
	}
}
