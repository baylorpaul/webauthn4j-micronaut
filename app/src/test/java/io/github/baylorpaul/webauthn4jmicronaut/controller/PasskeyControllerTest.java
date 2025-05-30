package io.github.baylorpaul.webauthn4jmicronaut.controller;

import io.github.baylorpaul.micronautjsonapi.model.*;
import io.github.baylorpaul.micronautjsonapi.util.JsonApiUtil;
import io.github.baylorpaul.webauthn4jmicronaut.entity.PasskeyCredentials;
import io.github.baylorpaul.webauthn4jmicronaut.security.jwt.TestCredentialsUtil;
import io.github.baylorpaul.webauthn4jmicronaut.util.JsonApiTestUtil;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.json.JsonMapper;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;

@MicronautTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class PasskeyControllerTest {

	private TestCredentialsUtil.TestCreds testCreds;

	@Inject
	@Client("/")
	private HttpClient client;

	@Inject
	private TestCredentialsUtil testCredentialsUtil;

	@Inject
	private JsonMapper jsonMapper;

	@BeforeAll
	public void init() {
		this.testCreds = testCredentialsUtil.createTestCreds();
		testCredentialsUtil.createPasskeyRecord(testCreds.userId());
	}

	private JsonApiArray getPasskeys() {
		HttpRequest<?> request = HttpRequest.GET(UriBuilder.of("/passkeys").queryParam("sort", "id,asc").toString())
				.accept(MediaType.APPLICATION_JSON)
				.bearerAuth(testCreds.accessToken());

		HttpResponse<JsonApiTopLevelArray> rsp = client.toBlocking().exchange(request, JsonApiTopLevelArray.class);
		JsonApiTopLevelArray tlArr = rsp.body();
		Assertions.assertNotNull(tlArr);
		JsonApiArray arr = tlArr.getData();
		Assertions.assertNotNull(arr);
		return arr;
	}

	@Test
	public void testGetPasskeys() {
		JsonApiArray arr = getPasskeys();

		Assertions.assertFalse(arr.isEmpty());
		Assertions.assertEquals(1, arr.size());

		JsonApiResource res = arr.getFirst();
		Assertions.assertEquals("passkey", res.getType());

		// Make sure no values are provided that we don't expect. That would be a major security issue.

		// We expect precisely these attributes, and no more.
		List<String> expectedAttrs = List.of("lastUsedDate", "passkeyName", "created", "updated");
		Set<String> attrs = res.getAttributes().keySet();
		Assertions.assertEquals(expectedAttrs.size(), attrs.size());
		for (String expectedKey : expectedAttrs) {
			Assertions.assertTrue(attrs.contains(expectedKey), "Expected to find key: " + expectedKey);
		}

		// This is a redundant check from above, but is extremely important.
		Assertions.assertFalse(res.getAttributes().containsKey("attestedCredentialData"));

		// We expect precisely these relationships, and no more.
		List<String> expectedRelationships = List.of("user");
		Set<String> relationships = res.getRelationships().keySet();
		Assertions.assertEquals(expectedRelationships.size(), relationships.size());
		for (String expectedRelationship : expectedRelationships) {
			Assertions.assertTrue(relationships.contains(expectedRelationship), "Expected to find relationship: " + expectedRelationship);
		}

		PasskeyCredentials pc = JsonApiUtil.readResourceWithId(jsonMapper, res, PasskeyCredentials.class)
				.orElseThrow(() -> new RuntimeException("Expected to find passkey credentials"));

		Assertions.assertNotNull(pc.getUser());
		Assertions.assertEquals(testCreds.userId(), pc.getUser().getId());
	}

	@Test
	public void testPasskeyCrudOps() {
		// We're not going to do the C (Create) in CRUD here since Passkeys aren't created by typical API calls.
		JsonApiArray arr = getPasskeys();

		Assertions.assertEquals(1, arr.size());
		JsonApiResource res = arr.getFirst();
		String passkeyId = res.getId();

		PasskeyCredentials pc = JsonApiUtil.readResourceWithId(jsonMapper, res, PasskeyCredentials.class)
				.orElseThrow(() -> new RuntimeException("Expected to find passkey credentials"));
		Assertions.assertNotNull(pc);

		pc = updatePasskey(pc);
		pc = readPasskey(passkeyId);
		deletePasskey(passkeyId);
	}

	private PasskeyCredentials updatePasskey(PasskeyCredentials pc1) {
		// Ensure the attributes match expected alternate values from what we're changing them to
		Assertions.assertNull(pc1.getPasskeyName());

		LinkedHashMap<String, Object> attrs = new LinkedHashMap<>();
		attrs.put("passkeyName", "My iPhone 15 Pro Max");

		JsonApiObject<?> body = JsonApiObject.builder()
				.data(JsonApiResource.builder()
						.type(pc1.toResourceType())
						.id(pc1.toJsonApiId())
						.attributes(attrs)
						.build()
				)
				.build();

		HttpRequest<?> request = HttpRequest.PATCH("/passkeys/" + pc1.getId(), body)
				.bearerAuth(testCreds.accessToken());

		HttpResponse<JsonApiTopLevelResource> rsp = client.toBlocking().exchange(request, JsonApiTopLevelResource.class);
		JsonApiTopLevelResource res = rsp.body();
		Assertions.assertNotNull(res);
		Assertions.assertNotNull(res.getData());

		PasskeyCredentials pc = JsonApiUtil.readResourceWithId(jsonMapper, res.getData(), PasskeyCredentials.class)
				.orElseThrow(() -> new RuntimeException("Expected to find passkey credentials"));
		Assertions.assertNotNull(pc);
		Assertions.assertTrue(pc.getId() > 0L);
		Assertions.assertNotNull(pc.getUser());
		Assertions.assertEquals(testCreds.userId(), pc.getUser().getId());
		Assertions.assertNull(pc.getLastUsedDate());
		Assertions.assertEquals("My iPhone 15 Pro Max", pc.getPasskeyName());

		return pc;
	}

	private PasskeyCredentials readPasskey(String passkeyId) {
		HttpRequest<?> request = HttpRequest.GET("/passkeys/" + passkeyId)
				.bearerAuth(testCreds.accessToken());

		HttpResponse<JsonApiTopLevelResource> rsp = client.toBlocking().exchange(request, JsonApiTopLevelResource.class);
		JsonApiTopLevelResource res = rsp.body();
		Assertions.assertNotNull(res);
		Assertions.assertNotNull(res.getData());

		PasskeyCredentials pc = JsonApiUtil.readResourceWithId(jsonMapper, res.getData(), PasskeyCredentials.class)
				.orElseThrow(() -> new RuntimeException("Expected to find passkey credentials"));
		Assertions.assertNotNull(pc);
		Assertions.assertTrue(pc.getId() > 0L);
		Assertions.assertNotNull(pc.getUser());
		Assertions.assertEquals(testCreds.userId(), pc.getUser().getId());

		return pc;
	}

	/**
	 * Delete the passkey
	 */
	private void deletePasskey(String passkeyId) {
		HttpRequest<?> req1 = HttpRequest.DELETE("/passkeys/" + passkeyId)
				.bearerAuth(testCreds.accessToken());

		HttpResponse<Object> rsp1 = client.toBlocking().exchange(req1);
		Assertions.assertEquals(HttpStatus.NO_CONTENT, rsp1.getStatus());

		// Now try to retrieve it again, and verify it's really gone
		HttpRequest<?> req2 = HttpRequest.GET("/passkeys/" + passkeyId)
				.bearerAuth(testCreds.accessToken());

		try {
			client.toBlocking().exchange(req2, JsonApiTopLevelResource.class);
			Assertions.fail("Expected to get a 'Not Found' response");
		} catch (HttpClientResponseException e) {
			JsonApiTestUtil.assertJsonApiErrorResponse(e, HttpStatus.NOT_FOUND,
					"Passkey not found"
			);
		}
	}
}
