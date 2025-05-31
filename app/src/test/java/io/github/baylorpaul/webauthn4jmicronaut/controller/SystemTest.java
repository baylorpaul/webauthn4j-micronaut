package io.github.baylorpaul.webauthn4jmicronaut.controller;

import com.webauthn4j.util.Base64Util;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.serialization.ByteArrayBase64UrlSerde;
import io.micronaut.core.annotation.ReflectiveAccess;
import io.micronaut.json.JsonMapper;
import io.micronaut.serde.annotation.Serdeable;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@MicronautTest
public class SystemTest {

	@Inject
	private JsonMapper jsonMapper;

	@Data
	@AllArgsConstructor
	@Serdeable
	@ReflectiveAccess
	private static class RegularClassWithByteArrayId {
		private byte[] id;
	}

	@Data
	@AllArgsConstructor
	@Serdeable
	@ReflectiveAccess
	private static class ClassWithByteArrayIdAndSerializer {
		@Serdeable.Serializable(using = ByteArrayBase64UrlSerde.class)
		private byte[] id;
	}

	@Test
	public void testGenPasskeyRegOpts() throws IOException {
		byte[] id = "!@#$%^&*()[]{};':\",.<>/?`~-=_+abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".getBytes(StandardCharsets.UTF_8);

		RegularClassWithByteArrayId regClass = new RegularClassWithByteArrayId(id);
		// If in the future we'd rather the default serialization for byte[] be Base64Url encoding (or other), that is
		// fine. The below is only testing the default. And below that, we test that explicitly using
		// ByteArrayBase64UrlSerde causes the serialization to use Base64Url encoding.
		Assertions.assertEquals(
				"{\"id\":[33,64,35,36,37,94,38,42,40,41,91,93,123,125,59,39,58,34,44,46,60,62,47,63,96,126,45,61,95,43,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,48,49,50,51,52,53,54,55,56,57]}",
				jsonMapper.writeValueAsString(regClass)
		);

		ClassWithByteArrayIdAndSerializer classWithSerializer = new ClassWithByteArrayIdAndSerializer(id);
		Assertions.assertEquals(
				// Expecting Base64Url encoding, not Base64 encoding. Notice the underscore character instead of a slash
				"{\"id\":\"IUAjJCVeJiooKVtde307JzoiLC48Pi8_YH4tPV8rYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXpBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWjAxMjM0NTY3ODk\"}",
				jsonMapper.writeValueAsString(classWithSerializer)
		);

		Assertions.assertEquals(
				// Expecting Base64 encoding, not Base64Url encoding. Notice the slash character instead of an underscore
				"IUAjJCVeJiooKVtde307JzoiLC48Pi8/YH4tPV8rYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXpBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWjAxMjM0NTY3ODk",
				Base64Util.encodeToString(id)
		);
	}
}
