package io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.serialization;

import com.webauthn4j.converter.util.JsonConverter;
import io.github.baylorpaul.webauthn4jmicronaut.util.PasskeyUtil;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.type.Argument;
import io.micronaut.json.JsonMapper;
import io.micronaut.json.tree.JsonNode;
import io.micronaut.serde.*;
import lombok.AllArgsConstructor;

import java.io.IOException;
import java.util.Map;

/**
 * A serializer/deserializer that relies on Jackson serialization/deserialization instead of Micronaut Serialization.
 * This is needed because some of the WebAuthn4J classes use @JsonValue on one of their fields to serialize the entire
 * object with just that single value. With Micronaut Serialization, this will cause a serialization issue if the object
 * is null. This serializer is to be applied to any classes that have a nullable member that is of a class that uses
 * <code>@JsonValue</code>. Then the null object will be serialized as null. Otherwise, we may encounter an error such as:
 * <code>NullPointerException: Cannot invoke "com.webauthn4j.data.AuthenticatorAttachment.getValue()" because "arg2" is null</code>.
 * Note that this is for the wrapping class, not the null object.
 * E.g. AuthenticatorSelectionCriteria, not AuthenticatorAttachment.
 * The error described comes from the path in io.micronaut.serde.support.serializers.CustomizedObjectSerializer under
 * the `case NON_EMPTY` when the bean is null, which calls ErrorCatchingSerializer.isEmpty() ->
 * JsonValueSerializer.isEmpty(), which retrieves a null bean, which it is not expecting.
 */
@AllArgsConstructor
public class GenericWebAuthn4JSerde<T> implements Serde<T> {

	private static final JsonConverter jsonConverter = PasskeyUtil.findObjectConverter().getJsonConverter();
	private static final JsonMapper jsonMapper = JsonMapper.createDefault();

	private Class<T> clazz;

	@Override
	public void serialize(
			@NonNull Encoder encoder, @NonNull EncoderContext context,
			@NonNull Argument<? extends T> type, @NonNull T value
	) throws IOException {
		// Write the object to JSON using Jackson
		final String jsonStr = jsonConverter.writeValueAsString(value);
		// Convert the JSON string to a map
		final Map<String, Object> map = jsonMapper.readValue(jsonStr, Map.class);
		// Serialize the map using JsonNodeSerde
		JsonNode jsonNode = JsonNode.from(map);
		Serializer<? super JsonNode> jsonNodeSerializer = context.findSerializer(JsonNode.class);
		jsonNodeSerializer.serialize(encoder, context, Argument.of(JsonNode.class), jsonNode);
	}

	@Override
	public @Nullable T deserialize(
			@NonNull Decoder decoder, @NonNull DecoderContext context, @NonNull Argument<? super T> type
	) throws IOException {
		// Deserialize using JsonNodeSerde
		Deserializer<? extends JsonNode> jsonNodeDeserializer = context.findDeserializer(JsonNode.class);
		JsonNode jsonNode = jsonNodeDeserializer.deserialize(decoder, context, Argument.of(JsonNode.class));
		// Convert the JsonNode to a JSON string
		String jsonStr = jsonMapper.writeValueAsString(jsonNode);
		// Read the value into the instance using Jackson
		return jsonConverter.readValue(jsonStr, clazz);
	}
}
