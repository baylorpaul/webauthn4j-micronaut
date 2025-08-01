package io.github.baylorpaul.webauthn4jmicronaut.controller;

import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.util.Base64UrlUtil;
import io.github.baylorpaul.micronautjsonapi.model.*;
import io.github.baylorpaul.micronautjsonapi.util.JsonApiUtil;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.PublicKeyCredentialCreationOptionsSessionDto;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.PublicKeyCredentialRequestOptionsSessionDto;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.submission.UserVerificationDto;
import io.github.baylorpaul.webauthn4jmicronaut.entity.PasskeyCredentials;
import io.github.baylorpaul.webauthn4jmicronaut.entity.User;
import io.github.baylorpaul.webauthn4jmicronaut.security.PasskeyConfigurationProperties;
import io.github.baylorpaul.webauthn4jmicronaut.security.jwt.TestCredentialsUtil;
import io.github.baylorpaul.webauthn4jmicronaut.security.passkey.model.PasskeyCredAndUserHandle;
import io.github.baylorpaul.webauthn4jmicronaut.service.PasskeyTestService;
import io.github.baylorpaul.webauthn4jmicronaut.service.mail.MockEmailService;
import io.github.baylorpaul.webauthn4jmicronaut.service.mail.template.PasskeyAdditionLinkEmailTemplate;
import io.github.baylorpaul.webauthn4jmicronaut.util.AuthenticationUtil;
import io.github.baylorpaul.webauthn4jmicronaut.util.JsonApiTestUtil;
import io.github.baylorpaul.webauthn4jmicronaut.util.PasskeyTestUtil;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.json.JsonMapper;
import io.micronaut.security.token.render.BearerAccessRefreshToken;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URISyntaxException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@MicronautTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class PasskeyControllerTest {

	@Inject
	@Client("/")
	private HttpClient client;

	@Inject
	private PasskeyTestService passkeyTestService;

	@Inject
	private TestCredentialsUtil testCredentialsUtil;

	@Inject
	private MockEmailService mockEmailService;

	@Inject
	private JsonMapper jsonMapper;

	@Inject
	private PasskeyConfigurationProperties passkeyConfigurationProps;

	private JsonApiArray getPasskeys(TestCredentialsUtil.TestCreds testCreds) {
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
	public void testRegistrationOptionsWithoutEmail() {
		try {
			// Test that we can't generate passkey registration options without a "uniqueNameOrEmail" param
			client.toBlocking().exchange(
					HttpRequest.GET("/passkeys/methods/generateRegistrationOptions"),
					PublicKeyCredentialCreationOptionsSessionDto.class
			);
			Assertions.fail("Expected to get a 'Not Found' response");
		} catch (HttpClientResponseException e) {
			JsonApiTestUtil.assertJsonApiErrorResponse(e, HttpStatus.BAD_REQUEST,
					"Required argument [String uniqueNameOrEmail] not specified"
			);
		}
	}

	/**
	 * Create a new user via passkey registration and then log in with that passkey
	 */
	@Test
	public void testUserRegistrationViaPasskeyAndLogin() {
		final String email = "brand-new-user23623@gmail.com";
		PublicKeyCredentialCreationOptionsSessionDto res = passkeyTestService.genRegOpts(email);

		PasskeyCredAndUserHandle credAndUserHandle = generatePasskeyCredWithUserHandle(res);
		AttestedCredentialData attestedCredentialData = credAndUserHandle.attestedCredentialDataIncludingPrivateKey();

		PasskeyCredentials pc = passkeyTestService.registerPasskey(res, attestedCredentialData);

		BearerAccessRefreshToken bearerAccessRefreshToken = passkeyTestService.logIn(credAndUserHandle);
	}

	@Test
	public void testVerifyAuthWithSignatureFromDifferentKey() {
		final String email = "brand-new-user13989@gmail.com";
		PublicKeyCredentialCreationOptionsSessionDto res = passkeyTestService.genRegOpts(email);

		PasskeyCredAndUserHandle credAndUserHandle = generatePasskeyCredWithUserHandle(res);
		AttestedCredentialData attestedCredentialData = credAndUserHandle.attestedCredentialDataIncludingPrivateKey();
		COSEKey coseKey = attestedCredentialData.getCOSEKey();

		PasskeyCredentials pc = passkeyTestService.registerPasskey(res, attestedCredentialData);

		PublicKeyCredentialRequestOptionsSessionDto dto = passkeyTestService.generateAuthOpts();

		String userHandleBase64Url = credAndUserHandle.userHandleBase64Url();
		String base64UrlCredentialId = Base64UrlUtil.encodeToString(attestedCredentialData.getCredentialId());

		// Get the authentication response but use a different key to sign the challenge
		COSEKey differentKey = PasskeyTestUtil.generateCOSEKey(true);

		assertAuthenticationVerificationFails(
				dto,
				userHandleBase64Url,
				base64UrlCredentialId,
				differentKey,
				HttpStatus.UNAUTHORIZED,
				"Invalid credentials and/or signature",
				"Expected the verification to fail because the signature was created with a different key"
		);

		// test that a valid path also fails because the session is invalidated by the above failure
		assertAuthenticationVerificationFails(
				dto,
				userHandleBase64Url,
				base64UrlCredentialId,
				// This is the right key, but the session is invalidated by the previous failure
				coseKey,
				HttpStatus.NOT_FOUND,
				"invalid or expired challenge session",
				"Expected the verification to fail because the challenge session was invalidated by the previous failure"
		);
	}

	/**
	 * @param coseKey the COSEKey to sign with, which may be a different key than the one used to register the passkey
	 *                   since we're testing failures
	 */
	private void assertAuthenticationVerificationFails(
			PublicKeyCredentialRequestOptionsSessionDto dto, String userHandleBase64Url, String base64UrlCredentialId,
			COSEKey coseKey, HttpStatus expectedHttpStatus, String expectedErrorMsg, String errorMsgOnSuccess
	) {
		Map<String, Object> authenticationResponse = PasskeyTestUtil.generatePasskeyAuthenticationResponse(
				passkeyConfigurationProps,
				userHandleBase64Url,
				base64UrlCredentialId,
				coseKey,
				dto.getPublicKeyCredentialRequestOptions().getChallenge()
		);

		try {
			passkeyTestService.verifyAuthentication(
					dto.getChallengeSessionId(),
					authenticationResponse,
					"/passkeys/methods/verifyAuthenticationForAccessTokenResponse",
					null,
					BearerAccessRefreshToken.class
			);
			Assertions.fail(errorMsgOnSuccess);
		} catch (HttpClientResponseException e) {
			JsonApiTestUtil.assertJsonApiErrorResponse(e, expectedHttpStatus, expectedErrorMsg);
		}
	}

	/**
	 * Register a new user with a passkey. Then, while logged out, authenticate to get a confirmation token. This is a
	 * rarely used, less-preferred authentication method. It is used for cases such as when a user attempts to log in to
	 * an existing account via federated login, but they've never associated the federated login with their account. So
	 * this allows the user to get a confirmation token, which may be used for a separate request to link their
	 * federated login to their account and then log in.
	 */
	@Test
	public void testUserRegistrationViaPasskeyAndGetConfirmationToken() {
		final String email = "brand-new-user78972@gmail.com";
		PublicKeyCredentialCreationOptionsSessionDto res = passkeyTestService.genRegOpts(email);

		PasskeyCredAndUserHandle credAndUserHandle = generatePasskeyCredWithUserHandle(res);
		AttestedCredentialData attestedCredentialData = credAndUserHandle.attestedCredentialDataIncludingPrivateKey();

		PasskeyCredentials pc = passkeyTestService.registerPasskey(res, attestedCredentialData);

		String jwtPasskeyAccessVerifiedToken = passkeyTestService.getPasskeyAccessVerifiedTokenFromPasskeyCreds(credAndUserHandle);

		// TODO use the "jwtPasskeyAccessVerifiedToken" to take a protected action while not otherwise authenticated,
		//  such as linking a federated login first the first time to an existing user account
	}

	private PasskeyCredAndUserHandle generatePasskeyCredWithUserHandle(PublicKeyCredentialCreationOptionsSessionDto res) {
		String userHandleBase64Url = Base64UrlUtil.encodeToString(
				res.getPublicKeyCredentialCreationOptions().getUser().getId()
		);
		return TestCredentialsUtil.generatePasskeyCredAndUserHandle(userHandleBase64Url);
	}

	@Test
	public void testRegistrationVerificationWithDiscardedChallenge() {
		final String email = "brand-new-user28683@gmail.com";
		PublicKeyCredentialCreationOptionsSessionDto res = passkeyTestService.genRegOpts(email);

		AttestedCredentialData attestedCredentialData = PasskeyTestUtil.generateAttestedCredentialData(true);

		// Don't use the provided challenge. Override it to something else
		try {
			Challenge challengeOverride = new DefaultChallenge();
			Map<String, Object> registrationResponseWithWrongChallenge = PasskeyTestUtil.generatePasskeyRegistrationResponse(
					passkeyConfigurationProps, res.getPublicKeyCredentialCreationOptions(), challengeOverride, attestedCredentialData
			);
			passkeyTestService.verifyRegistration(res.getChallengeSessionId(), registrationResponseWithWrongChallenge);
			Assertions.fail("Expected the registration to fail because of the mismatched challenge");
		} catch (HttpClientResponseException e) {
			JsonApiTestUtil.assertJsonApiErrorResponse(e, HttpStatus.UNAUTHORIZED,
					"Invalid credentials"
			);
		}

		// Now try with the correct challenge, but this request should fail because the previous request with the
		// challenge session ID has caused the correct challenge to be discarded
		try {
			Map<String, Object> registrationResponse = PasskeyTestUtil.generatePasskeyRegistrationResponse(
					passkeyConfigurationProps, res.getPublicKeyCredentialCreationOptions(), null, attestedCredentialData
			);
			passkeyTestService.verifyRegistration(res.getChallengeSessionId(), registrationResponse);
			Assertions.fail("Expected the registration to fail because the challenge was previously discarded");
		} catch (HttpClientResponseException e) {
			JsonApiTestUtil.assertJsonApiErrorResponse(e, HttpStatus.NOT_FOUND,
					"invalid or expired challenge session"
			);
		}
	}

	/**
	 * Test the "lost my passkey" flow. This uses ConfirmationType.PASSKEY_ADDITION.
	 * Generate passkey registration options for an existing, yet unauthenticated, account via confirmation token.
	 */
	@Test
	public void testGenPasskeyRegOptsViaTokenForExistingAccount() throws URISyntaxException {
		final String userEmail = "brand-new-user48417@gmail.com";
		final User user = testCredentialsUtil.createUserWithPasskeyCredsViaServiceCalls(userEmail);

		// The URI where the token will be added. As opposed to "password reset" emails, etc., the web app
		// implements this webpage because the passkey "Relying Party" (RP) ID and origin URL must match the web app.
		final String addPasskeyUriPathWithoutToken = "/login/addPasskeyViaToken";

		// This should work whether the user's email is verified or not
		PasskeyAdditionLinkEmailTemplate template = sendPasskeyResetLinkEmail(user.getEmail(), addPasskeyUriPathWithoutToken);
		Assertions.assertNotNull(template);

		PublicKeyCredentialCreationOptionsSessionDto res = passkeyTestService.generateRegistrationOptionsForExistingAccount(
				user, addPasskeyUriPathWithoutToken, template.getWebPasskeyAdditionUrl()
		);

		// Should not be able to generate passkey registration options a second time with the same token
		try {
			passkeyTestService.generateRegistrationOptionsForExistingAccount(
					user, addPasskeyUriPathWithoutToken, template.getWebPasskeyAdditionUrl()
			);
			Assertions.fail("Expected to get a 'Gone' response");
		} catch (HttpClientResponseException e) {
			JsonApiTestUtil.assertJsonApiErrorResponse(e, HttpStatus.GONE,
					"Confirmation token has already been utilized"
			);
		}

		AttestedCredentialData attestedCredentialData = PasskeyTestUtil.generateAttestedCredentialData(true);
		Map<String, Object> registrationResponse = PasskeyTestUtil.generatePasskeyRegistrationResponse(
				passkeyConfigurationProps, res.getPublicKeyCredentialCreationOptions(), null, attestedCredentialData
		);
		PasskeyCredentials pc = passkeyTestService.verifyRegistration(res.getChallengeSessionId(), registrationResponse);
		Assertions.assertEquals(user.getId(), pc.getUser().getId());
	}

	/**
	 * Send a "lost my passkey" email.
	 * The email includes a link with a token that can be used to add a passkey to the user.
	 */
	private PasskeyAdditionLinkEmailTemplate sendPasskeyResetLinkEmail(
			String email, String addPasskeyUriPathWithoutToken
	) {
		HttpResponse<?> rsp = client.toBlocking().exchange(
				HttpRequest.POST(
						"/users/methods/sendPasskeyAdditionLinkEmail",
						Map.of(
								"addPasskeyUriPathWithoutToken", addPasskeyUriPathWithoutToken,
								"email", email
						)
				)
		);
		Assertions.assertEquals(HttpStatus.OK, rsp.getStatus());

		// Get contents sent in the email
		return mockEmailService.assertAndReadLastEmailContentValue(PasskeyAdditionLinkEmailTemplate.class);
	}

	/**
	 * Add a passkey to an existing account that is already authenticated, using password credentials to re-verify
	 * access. The user may re-verify via one of multiple authentication methods, but this test only uses the password
	 * option.
	 */
	@Test
	public void testRegisterNewPasskeyAsAuthenticatedUserUsingAPasswordToConfirmAccess() {
		if (AuthenticationUtil.PASSWORD_AUTHENTICATION_ENABLED) {
			TestCredentialsUtil.TestCreds testCreds = testCredentialsUtil.createTestCredsWithPassword();
			UserVerificationDto userVerificationDto = UserVerificationDto.builder()
					.platform("web")
					.jwtPasskeyAccessVerifiedToken(null)
					.password(TestCredentialsUtil.TEST_PASSWORD)
					.build();

			AttestedCredentialData attestedCredentialData = PasskeyTestUtil.generateAttestedCredentialData(true);
			registerPasskeyWithConfirmedUserAccess(testCreds, userVerificationDto, attestedCredentialData);
		}
	}

	/**
	 * Add a passkey to an existing account that is already authenticated, using pre-existing passkey credentials to
	 * re-verify access. The user may re-verify via one of multiple authentication methods, but this test only uses the
	 * passkey option. When the user re-authenticates with a passkey, the server will generate a short-lived token. That
	 * token is used to confirm access when creating a new passkey. This uses ConfirmationType.PASSKEY_ACCESS_VERIFIED.
	 */
	@Test
	public void testRegisterNewPasskeyAsAuthenticatedUserUsingAPreExistingPasskeyToConfirmAccess() {
		TestCredentialsUtil.TestCreds testCreds = testCredentialsUtil.createUserAndAccessTokenWithPasskeyCredsViaServiceCalls(
				TestCredentialsUtil.generateRandomEmail()
		);

		// First, make sure we have a passkey, with which we'll re-verify access to the user's account
		PasskeyCredAndUserHandle credAndUserHandle = testCredentialsUtil.createAndPersistPasskeyRecordByUserId(testCreds.userId());

		// Re-verify user access. We'll use that confirmation token to generate passkey registration options.
		// Those registration options will subsequently be used to add another passkey to the user's account.
		UserVerificationDto userVerificationDto = passkeyTestService.reVerifyUserAccessViaPasskey(
				testCreds.accessToken(), credAndUserHandle
		);

		// Making a separate passkey, so make new AttestedCredentialData.
		// Don't reuse credAndUserHandle.attestedCredentialDataIncludingPrivateKey().
		// Even if we tried to reuse it, we'd get a conflict due to a reuse of a credential ID.
		AttestedCredentialData newAttestedCredentialData = PasskeyTestUtil.generateAttestedCredentialData(true);
		registerPasskeyWithConfirmedUserAccess(testCreds, userVerificationDto, newAttestedCredentialData);
	}

	private void registerPasskeyWithConfirmedUserAccess(
			TestCredentialsUtil.TestCreds testCreds,
			@NonNull UserVerificationDto userVerificationDto, @NonNull AttestedCredentialData attestedCredentialData
	) {
		// Generate passkey registration options that will be used to add a new passkey to the user's account.
		PublicKeyCredentialCreationOptionsSessionDto res = genRegOptsAsAuthenticatedUser(testCreds, userVerificationDto);

		// Now verify the registration of a new passkey
		registerAndAssertPasskeyCredsCreatedForTestUser(testCreds, res, attestedCredentialData);
	}

	@Test
	public void testConfirmationTokenReuseForGenPasskeyRegOpts() {
		TestCredentialsUtil.TestCreds testCreds = testCredentialsUtil.createUserAndAccessTokenWithPasskeyCredsViaServiceCalls(
				TestCredentialsUtil.generateRandomEmail()
		);
		PasskeyCredAndUserHandle credAndUserHandle = testCredentialsUtil.createAndPersistPasskeyRecordByUserId(testCreds.userId());
		UserVerificationDto userVerificationDto = passkeyTestService.reVerifyUserAccessViaPasskey(
				testCreds.accessToken(), credAndUserHandle
		);

		// The first attempt to use the confirmation token should succeed
		PublicKeyCredentialCreationOptionsSessionDto res1 = genRegOptsAsAuthenticatedUser(testCreds, userVerificationDto);

		// Making a separate passkey, so make new AttestedCredentialData.
		// Don't reuse credAndUserHandle.attestedCredentialDataIncludingPrivateKey().
		// Even if we tried to reuse it, we'd get a conflict due to a reuse of a credential ID.
		AttestedCredentialData newAttestedCredentialData = PasskeyTestUtil.generateAttestedCredentialData(true);

		// The second attempt should fail due to token reuse
		try {
			genRegOptsAsAuthenticatedUser(testCreds, userVerificationDto);
			Assertions.fail("Expected to get a 'Gone' response");
		} catch (HttpClientResponseException e) {
			JsonApiTestUtil.assertJsonApiErrorResponse(e, HttpStatus.GONE,
					"Confirmation token has already been utilized"
			);
		}

		// The original options are still valid
		registerAndAssertPasskeyCredsCreatedForTestUser(testCreds, res1, newAttestedCredentialData);

		// Now the challenge is discarded, so the original options are no longer valid
		try {
			registerAndAssertPasskeyCredsCreatedForTestUser(testCreds, res1, newAttestedCredentialData);
			Assertions.fail("Expected to get a 'Not Found' response");
		} catch (HttpClientResponseException e) {
			JsonApiTestUtil.assertJsonApiErrorResponse(e, HttpStatus.NOT_FOUND,
					"invalid or expired challenge session"
			);
		}
	}

	private PublicKeyCredentialCreationOptionsSessionDto genRegOptsAsAuthenticatedUser(
			TestCredentialsUtil.TestCreds testCreds, UserVerificationDto userVerificationDto
	) {
		User user = testCredentialsUtil.findUser(testCreds);
		return passkeyTestService.genRegOptsAsAuthenticatedUser(
				testCreds.accessToken(), userVerificationDto,
				user.getEmail(), user.getName()
		);
	}

	/**
	 * Register a new passkey and verify it for the test user
	 */
	private void registerAndAssertPasskeyCredsCreatedForTestUser(
			TestCredentialsUtil.TestCreds testCreds,
			PublicKeyCredentialCreationOptionsSessionDto res, AttestedCredentialData attestedCredentialData
	) {
		PasskeyCredentials pc = passkeyTestService.registerPasskey(res, attestedCredentialData);
		Assertions.assertEquals(testCreds.userId(), pc.getUser().getId());
	}

	/**
	 * Via API calls, create a user with a passkey
	 */
	@Test
	public void testCreateUserWithPasskeyAndRetrieveUserRecord() {
		final String email = "brand-new-user42578@gmail.com";
		TestCredentialsUtil.TestCreds creds = testCredentialsUtil.createUserAndAccessTokenWithPasskeyCredsViaApiCalls(email);

		HttpResponse<JsonApiTopLevelResource> userRsp = client.toBlocking().exchange(
				HttpRequest.GET("/users/me")
						.accept(MediaType.APPLICATION_JSON)
						.bearerAuth(creds.accessToken()),
				JsonApiTopLevelResource.class
		);
		JsonApiTopLevelResource tlRes = userRsp.body();
		User user = JsonApiUtil.readResourceWithId(jsonMapper, tlRes.getData(), User.class)
				.orElseThrow(() -> new RuntimeException("Expected to find user"));

		Assertions.assertEquals(creds.userId(), user.getId());
		Assertions.assertEquals(email, user.getEmail());
	}

	@Test
	public void testGetPasskeys() {
		TestCredentialsUtil.TestCreds testCreds = testCredentialsUtil.createUserAndAccessTokenWithPasskeyCredsViaServiceCalls(
				TestCredentialsUtil.generateRandomEmail()
		);

		JsonApiArray arr = getPasskeys(testCreds);

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
		TestCredentialsUtil.TestCreds testCreds = testCredentialsUtil.createUserAndAccessTokenWithPasskeyCredsViaServiceCalls(
				TestCredentialsUtil.generateRandomEmail()
		);

		// We're not going to do the C (Create) in CRUD here since Passkeys aren't created by typical API calls.
		JsonApiArray arr = getPasskeys(testCreds);

		Assertions.assertEquals(1, arr.size());
		JsonApiResource res = arr.getFirst();
		String passkeyId = res.getId();

		PasskeyCredentials pc = JsonApiUtil.readResourceWithId(jsonMapper, res, PasskeyCredentials.class)
				.orElseThrow(() -> new RuntimeException("Expected to find passkey credentials"));
		Assertions.assertNotNull(pc);

		pc = updatePasskey(testCreds, pc);
		pc = readPasskey(testCreds, passkeyId);
		deletePasskey(testCreds, passkeyId);
	}

	private PasskeyCredentials updatePasskey(TestCredentialsUtil.TestCreds testCreds, PasskeyCredentials pc1) {
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

		PasskeyCredentials pc = passkeyTestService.readAndAssertPasskeyCredentials(res.getData());
		Assertions.assertEquals(testCreds.userId(), pc.getUser().getId());
		Assertions.assertNull(pc.getLastUsedDate());
		Assertions.assertEquals("My iPhone 15 Pro Max", pc.getPasskeyName());

		return pc;
	}

	private PasskeyCredentials readPasskey(TestCredentialsUtil.TestCreds testCreds, String passkeyId) {
		HttpRequest<?> request = HttpRequest.GET("/passkeys/" + passkeyId)
				.bearerAuth(testCreds.accessToken());

		HttpResponse<JsonApiTopLevelResource> rsp = client.toBlocking().exchange(request, JsonApiTopLevelResource.class);
		JsonApiTopLevelResource res = rsp.body();
		Assertions.assertNotNull(res);
		Assertions.assertNotNull(res.getData());

		PasskeyCredentials pc = passkeyTestService.readAndAssertPasskeyCredentials(res.getData());
		Assertions.assertEquals(testCreds.userId(), pc.getUser().getId());
		return pc;
	}

	/**
	 * Delete the passkey
	 */
	private void deletePasskey(TestCredentialsUtil.TestCreds testCreds, String passkeyId) {
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
