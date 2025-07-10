package io.github.baylorpaul.webauthn4jmicronaut.service;

import com.github.dockerjava.zerodep.shaded.org.apache.hc.core5.http.NameValuePair;
import com.github.dockerjava.zerodep.shaded.org.apache.hc.core5.net.URLEncodedUtils;
import com.webauthn4j.data.PublicKeyCredentialCreationOptions;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.PublicKeyCredentialUserEntity;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import io.github.baylorpaul.micronautjsonapi.model.JsonApiResource;
import io.github.baylorpaul.micronautjsonapi.model.JsonApiTopLevelResource;
import io.github.baylorpaul.micronautjsonapi.util.JsonApiUtil;
import io.github.baylorpaul.webauthn4jmicronaut.ApplicationConfigurationProperties;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.PublicKeyCredentialCreationOptionsSessionDto;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.PublicKeyCredentialRequestOptionsSessionDto;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.submission.UserVerificationDto;
import io.github.baylorpaul.webauthn4jmicronaut.entity.PasskeyCredentials;
import io.github.baylorpaul.webauthn4jmicronaut.entity.User;
import io.github.baylorpaul.webauthn4jmicronaut.security.PasskeyConfigurationProperties;
import io.github.baylorpaul.webauthn4jmicronaut.security.passkey.model.PasskeyCredAndUserHandle;
import io.github.baylorpaul.webauthn4jmicronaut.util.PasskeyTestUtil;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.json.JsonMapper;
import jakarta.annotation.Nullable;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.validation.constraints.NotNull;
import org.junit.jupiter.api.Assertions;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

@Singleton
public class PasskeyTestService {

	@Inject
	@Client("/")
	private HttpClient client;

	@Inject
	private ApplicationConfigurationProperties appProps;

	@Inject
	private PasskeyConfigurationProperties passkeyProps;

	@Inject
	private JsonMapper jsonMapper;

	@Inject
	private JsonService jsonService;

	public String getConfirmationTokenFromPasskeyCreds(PasskeyCredAndUserHandle credAndUserHandle) {
		PublicKeyCredentialRequestOptionsSessionDto dto = generateAuthOpts();

		Map<String, Object> authenticationResponse = PasskeyTestUtil.generatePasskeyAuthenticationResponse(
				passkeyProps, dto.getPublicKeyCredentialRequestOptions(), credAndUserHandle, null
		);

		// Get a short-lived confirmation token that confirms user access to take a protected action, such as
		// associating a federated login for the first time with the user's account
		return verifyAuthentication(
				dto.getChallengeSessionId(),
				authenticationResponse,
				"/passkeys/methods/verifyAuthenticationForConfirmationTokenResponse",
				null,
				String.class
		);
	}

	public PublicKeyCredentialCreationOptionsSessionDto genRegOpts(String email) {
		final String displayName = "John Wick";

		// Generate passkey registration options for a new user
		HttpResponse<PublicKeyCredentialCreationOptionsSessionDto> rsp = client.toBlocking().exchange(
				HttpRequest.GET(
						UriBuilder.of("/passkeys/methods/generateRegistrationOptions")
								.queryParam("uniqueNameOrEmail", email)
								.queryParam("displayName", displayName)
								.toString()
				),
				PublicKeyCredentialCreationOptionsSessionDto.class
		);
		Assertions.assertEquals(HttpStatus.OK, rsp.getStatus());

		PublicKeyCredentialCreationOptionsSessionDto res = rsp.body();
		assertValidPublicKeyCredentialCreationOptionsSessionDto(res, email, displayName);
		return res;
	}

	private static void assertValidPublicKeyCredentialCreationOptionsSessionDto(
			PublicKeyCredentialCreationOptionsSessionDto res, String expectedEmail, String expectedDisplayName
	) {
		Assertions.assertNotNull(res);
		PublicKeyCredentialCreationOptions creationOpts = res.getPublicKeyCredentialCreationOptions();
		Assertions.assertNotNull(creationOpts);
		PublicKeyCredentialUserEntity user = creationOpts.getUser();
		Assertions.assertNotNull(user);

		Assertions.assertEquals(expectedEmail, user.getName());
		Assertions.assertEquals(expectedDisplayName, user.getDisplayName());
		Assertions.assertNotNull(creationOpts.getTimeout());

		List<PublicKeyCredentialParameters> pubKeyCredParams = creationOpts.getPubKeyCredParams();
		Assertions.assertNotNull(pubKeyCredParams);

		Assertions.assertTrue(pubKeyCredParams.stream()
				.allMatch(p -> p.getType().getValue().equals(
						PublicKeyCredentialType.PUBLIC_KEY.getValue()
				))
		);
		List<COSEAlgorithmIdentifier> expectedAlgs = List.of(
				COSEAlgorithmIdentifier.EdDSA,
				COSEAlgorithmIdentifier.ES256,
				COSEAlgorithmIdentifier.RS256
		);
		Assertions.assertTrue(expectedAlgs.stream()
				.allMatch(expectedAlg -> pubKeyCredParams.stream()
						.anyMatch(p -> p.getAlg().getValue() == expectedAlg.getValue())
				)
		);
	}

	public PasskeyCredentials verifyRegistration(UUID challengeSessionId, Map<String, Object> registrationResponse) {
		String registrationResponseJSON = jsonService.toJson(registrationResponse);

		HttpResponse<JsonApiTopLevelResource> rsp = client.toBlocking().exchange(
				HttpRequest.POST("/passkeys/methods/verifyRegistration", registrationResponseJSON)
						.header("X-Challenge-Session-ID", challengeSessionId.toString()),
				JsonApiTopLevelResource.class
		);
		Assertions.assertEquals(HttpStatus.CREATED, rsp.getStatus());

		JsonApiTopLevelResource res = rsp.body();
		Assertions.assertNotNull(res);
		Assertions.assertNotNull(res.getData());

		return readAndAssertPasskeyCredentials(res.getData());
	}

	public <T> T verifyAuthentication(
			UUID challengeSessionId, Map<String, Object> authenticationResponse, String verificationUri,
			@Nullable Consumer<MutableHttpRequest<?>> requestModifier, Class<T> clazz
	) {
		String authenticationResponseJSON = jsonService.toJson(authenticationResponse);

		MutableHttpRequest<?> request = HttpRequest.POST(verificationUri, authenticationResponseJSON)
				.header("X-Challenge-Session-ID", challengeSessionId.toString());
		if (requestModifier != null) {
			requestModifier.accept(request);
		}
		HttpResponse<T> rsp = client.toBlocking().exchange(
				request,
				clazz
		);
		Assertions.assertEquals(HttpStatus.OK, rsp.getStatus());

		T res = rsp.body();
		Assertions.assertNotNull(res);

		return res;
	}

	public PublicKeyCredentialCreationOptionsSessionDto generateRegistrationOptionsForExistingAccount(
			User user, String addPasskeyUriPathWithoutToken, String webPasskeyAdditionUrl
	) throws URISyntaxException {
		String expectedUrlStartsWith = appProps.getWebAppUrl() + addPasskeyUriPathWithoutToken + "?token=";
		Assertions.assertTrue(webPasskeyAdditionUrl.startsWith(expectedUrlStartsWith));

		List<NameValuePair> params = URLEncodedUtils.parse(new URI(webPasskeyAdditionUrl), StandardCharsets.UTF_8);
		Assertions.assertEquals(2, params.size());

		int paramIdx = -1;

		NameValuePair tokenPair = params.get(++paramIdx);
		Assertions.assertEquals("token", tokenPair.getName());
		String token = tokenPair.getValue();

		// The "email" param is provided for display purposes
		NameValuePair emailPair = params.get(++paramIdx);
		Assertions.assertEquals("email", emailPair.getName());
		Assertions.assertEquals(user.getEmail(), emailPair.getValue());

		HttpResponse<PublicKeyCredentialCreationOptionsSessionDto> rsp = client.toBlocking().exchange(
				HttpRequest.POST(
						"/passkeys/methods/generateRegistrationOptionsForExistingAccount",
						Map.of("token", token)
				),
				PublicKeyCredentialCreationOptionsSessionDto.class
		);
		Assertions.assertEquals(HttpStatus.OK, rsp.getStatus());

		PublicKeyCredentialCreationOptionsSessionDto res = rsp.body();
		assertValidPublicKeyCredentialCreationOptionsSessionDto(res, user.getEmail(), user.getName());

		return res;
	}

	public PublicKeyCredentialCreationOptionsSessionDto genRegOptsAsAuthenticatedUser(
			String accessToken, UserVerificationDto userVerificationDto,
			String expectedEmail, String expectedDisplayName
	) {
		String userVerificationJSON = jsonService.toJson(userVerificationDto);

		MutableHttpRequest<?> req = HttpRequest.POST(
				"/passkeys/methods/generateRegistrationOptionsAsAuthenticatedUser",
				userVerificationJSON
		).bearerAuth(accessToken);

		HttpResponse<PublicKeyCredentialCreationOptionsSessionDto> rsp = client.toBlocking().exchange(
				req,
				PublicKeyCredentialCreationOptionsSessionDto.class
		);
		Assertions.assertEquals(HttpStatus.OK, rsp.getStatus());

		PublicKeyCredentialCreationOptionsSessionDto res = rsp.body();
		assertValidPublicKeyCredentialCreationOptionsSessionDto(
				res, expectedEmail, expectedDisplayName
		);

		return res;
	}

	/**
	 * Register a new passkey
	 */
	public PasskeyCredentials registerPasskey(
			PublicKeyCredentialCreationOptionsSessionDto res, AttestedCredentialData attestedCredentialData
	) {
		Map<String, Object> registrationResponse = PasskeyTestUtil.generatePasskeyRegistrationResponse(
				passkeyProps, res.getPublicKeyCredentialCreationOptions(), null, attestedCredentialData
		);
		PasskeyCredentials pc = verifyRegistration(res.getChallengeSessionId(), registrationResponse);
		// Verify the user exists and has a passkey by checking if there is a user ID
		Assertions.assertTrue(pc.getUser().getId() > 0L);
		return pc;
	}

	/**
	 * Re-verify user access as an authenticated user in exchange for a short-lived confirmation token that can be used
	 * to take protected actions. E.g. adding an integration token, changing a user's password, or adding another
	 * passkey to the user's account.
	 */
	public UserVerificationDto reVerifyUserAccessViaPasskey(
			String accessToken, PasskeyCredAndUserHandle credAndUserHandle
	) {
		// Re-confirm the user has access to the account by re-signing in via passkey in exchange for a short-lived
		// token. This method expects the user to already be signed in. This is NOT a "lost my passkey" method.
		String passkeyAccessVerifiedToken = reVerifyPasskeyAuthenticationForConfirmationToken(
				accessToken, credAndUserHandle
		);
		Assertions.assertNotNull(passkeyAccessVerifiedToken);

		return UserVerificationDto.builder()
				.platform("web")
				.jwtPasskeyAccessVerifiedToken(passkeyAccessVerifiedToken)
				.password(null)
				.build();
	}

	/**
	 * Re-confirm the user has access to the account by re-signing in via passkey in exchange for a short-lived token.
	 * These methods expect the user to already be signed in.
	 * @return a "passkey access verified" confirmation token. This token is used to take a protected action that
	 *             requires confirming user access. E.g. adding an integration token, changing a user's password, or
	 *             adding another passkey to the user's account.
	 */
	private String reVerifyPasskeyAuthenticationForConfirmationToken(
			@NotNull String accessToken, @NotNull PasskeyCredAndUserHandle credAndUserHandle
	) {
		PublicKeyCredentialRequestOptionsSessionDto dto = generateAuthOptsAsAuthenticatedUser(accessToken);

		Map<String, Object> authenticationResponse = PasskeyTestUtil.generatePasskeyAuthenticationResponse(
				passkeyProps, dto.getPublicKeyCredentialRequestOptions(), credAndUserHandle, null
		);

		return verifyAuthentication(
				dto.getChallengeSessionId(),
				authenticationResponse,
				"/passkeys/methods/verifyAuthenticationAsAuthenticatedUserForConfirmationTokenResponse",
				req -> req.bearerAuth(accessToken),
				String.class
		);
	}

	public PublicKeyCredentialRequestOptionsSessionDto generateAuthOpts() {
		HttpRequest<?> request = HttpRequest.GET("/passkeys/methods/generateAuthenticationOptions");
		HttpResponse<PublicKeyCredentialRequestOptionsSessionDto> rsp = client.toBlocking().exchange(
				request,
				PublicKeyCredentialRequestOptionsSessionDto.class
		);
		PublicKeyCredentialRequestOptionsSessionDto dto = rsp.body();
		Assertions.assertNotNull(dto);
		return dto;
	}

	private PublicKeyCredentialRequestOptionsSessionDto generateAuthOptsAsAuthenticatedUser(String accessToken) {
		HttpRequest<?> request = HttpRequest.GET("/passkeys/methods/generateAuthenticationOptionsAsAuthenticatedUser")
				.bearerAuth(accessToken);
		HttpResponse<PublicKeyCredentialRequestOptionsSessionDto> rsp = client.toBlocking().exchange(
				request,
				PublicKeyCredentialRequestOptionsSessionDto.class
		);
		PublicKeyCredentialRequestOptionsSessionDto dto = rsp.body();
		Assertions.assertNotNull(dto);
		return dto;
	}

	public PasskeyCredentials readAndAssertPasskeyCredentials(JsonApiResource data) {
		PasskeyCredentials pc = JsonApiUtil.readResourceWithId(jsonMapper, data, PasskeyCredentials.class)
				.orElseThrow(() -> new RuntimeException("Expected to find passkey credentials"));
		Assertions.assertNotNull(pc);
		Assertions.assertTrue(pc.getId() > 0L);
		Assertions.assertNotNull(pc.getUser());
		return pc;
	}
}
