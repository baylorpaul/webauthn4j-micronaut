package io.github.baylorpaul.webauthn4jmicronaut.service;

import io.micronaut.json.JsonMapper;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import java.io.IOException;

/**
 * A service to serialize and deserialize JSON. This is a service instead of a utility class because we need a
 * JsonMapper with custom serializers/deserializers, not a static JsonMapper.
 */
@Singleton
public class JsonService {

	/**
	 * The JsonMapper. We're not just using a static value of JsonMapper.createDefault() because we need access to
	 * custom serializers and deserializers.
	 */
	@Inject
	private JsonMapper jsonMapper;

	public <T> T fromJson(String str, Class<T> clazz) {
		try {
			return jsonMapper.readValue(str, clazz);
		} catch (IOException e) {
			throw new RuntimeException("Unable to map JSON string [class: " + clazz.getCanonicalName() + ", str: " + str + "]", e);
		}
	}

	public String toJson(Object obj) {
		try {
			return obj == null ? "null" : jsonMapper.writeValueAsString(obj);
		} catch (IOException e) {
			throw new RuntimeException("Unable to write object as JSON", e);
		}
	}
}
