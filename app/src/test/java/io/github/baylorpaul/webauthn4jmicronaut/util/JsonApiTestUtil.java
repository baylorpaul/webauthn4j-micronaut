package io.github.baylorpaul.webauthn4jmicronaut.util;

import io.github.baylorpaul.micronautjsonapi.model.JsonApiError;
import io.github.baylorpaul.micronautjsonapi.model.JsonApiErrorResponse;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import org.junit.jupiter.api.Assertions;

import java.util.List;

public class JsonApiTestUtil {

	public static void assertJsonApiErrorResponse(
			@NonNull HttpClientResponseException e, @NonNull HttpStatus status, @Nullable String expectedErrorMsg
	) {
		assertJsonApiErrorResponse(e, status, null, expectedErrorMsg);
	}

	public static void assertJsonApiErrorResponse(
			@NonNull HttpClientResponseException e, @NonNull HttpStatus status, @Nullable String statusReasonOverride,
			@Nullable String expectedErrorMsg
	) {
		Assertions.assertEquals(status, e.getStatus());
		JsonApiErrorResponse errRsp = e.getResponse().getBody(JsonApiErrorResponse.class)
				.orElseThrow(() -> new RuntimeException("Expected to find error response"));

		if (statusReasonOverride != null) {
			Assertions.assertEquals(statusReasonOverride, errRsp.getMessage());
		} else {
			Assertions.assertEquals(status.getReason(), errRsp.getMessage());
		}

		List<JsonApiError> errors = errRsp.getErrors();
		Assertions.assertNotNull(errors);
		Assertions.assertEquals(1, errors.size());

		JsonApiError err = errors.getFirst();
		Assertions.assertEquals(String.valueOf(status.getCode()), err.getStatus());
		Assertions.assertEquals(expectedErrorMsg, err.getDetail());
	}
}
