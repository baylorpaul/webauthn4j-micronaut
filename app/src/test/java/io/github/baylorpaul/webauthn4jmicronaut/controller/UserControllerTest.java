package io.github.baylorpaul.webauthn4jmicronaut.controller;

import io.github.baylorpaul.micronautjsonapi.model.JsonApiResource;
import io.github.baylorpaul.micronautjsonapi.model.JsonApiTopLevelResource;
import io.github.baylorpaul.micronautjsonapi.util.JsonApiUtil;
import io.github.baylorpaul.webauthn4jmicronaut.entity.User;
import io.github.baylorpaul.webauthn4jmicronaut.security.jwt.TestCredentialsUtil;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.json.JsonMapper;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

@MicronautTest
public class UserControllerTest {

	private TestCredentialsUtil.TestCreds testCreds;

	@Inject
	@Client("/")
	private HttpClient client;

	@Inject
	private TestCredentialsUtil testCredentialsUtil;

	@Inject
	private JsonMapper jsonMapper;

	@BeforeEach
	public void init() {
		this.testCreds = testCredentialsUtil.createTestCreds();
	}

	@Test
	public void testGetMyUserWithoutId() {
		HttpRequest<?> request = HttpRequest.GET("/users/me")
				.accept(MediaType.APPLICATION_JSON)
				.bearerAuth(testCreds.accessToken());

		JsonApiResource res = readJsonApiResource(request);

		Assertions.assertEquals("user", res.getType());
		Assertions.assertEquals(Long.toString(testCreds.userId()), res.getId());

		Map<String, Object> attrs = res.getAttributes();
		Assertions.assertEquals(TestCredentialsUtil.TEST_EMAIL, attrs.get("email"));
		Assertions.assertEquals(TestCredentialsUtil.TEST_NAME, attrs.get("name"));

		User user = JsonApiUtil.readResourceWithId(jsonMapper, res, User.class)
				.orElseThrow(() -> new RuntimeException("Expected to find user"));
		Assertions.assertNotNull(user);
		Assertions.assertEquals(testCreds.userId(), user.getId());
		Assertions.assertEquals(TestCredentialsUtil.TEST_EMAIL, user.getEmail());
		Assertions.assertEquals(TestCredentialsUtil.TEST_NAME, user.getName());
	}

	private @NonNull JsonApiResource readJsonApiResource(HttpRequest<?> request) {
		HttpResponse<JsonApiTopLevelResource> rsp = client.toBlocking().exchange(request, JsonApiTopLevelResource.class);
		JsonApiTopLevelResource tlRes = rsp.body();
		Assertions.assertNotNull(tlRes);
		JsonApiResource res = tlRes.getData();
		Assertions.assertNotNull(res);
		return res;
	}
}
