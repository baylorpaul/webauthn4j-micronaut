package io.github.baylorpaul.webauthn4jmicronaut.controller;

import com.github.dockerjava.zerodep.shaded.org.apache.hc.core5.http.NameValuePair;
import com.github.dockerjava.zerodep.shaded.org.apache.hc.core5.net.URLEncodedUtils;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.util.Base64UrlUtil;
import io.github.baylorpaul.micronautjsonapi.model.*;
import io.github.baylorpaul.micronautjsonapi.util.JsonApiUtil;
import io.github.baylorpaul.webauthn4jmicronaut.ApplicationConfigurationProperties;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.PublicKeyCredentialCreationOptionsSessionDto;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.PublicKeyCredentialRequestOptionsSessionDto;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.submission.UserVerificationDto;
import io.github.baylorpaul.webauthn4jmicronaut.entity.PasskeyCredentials;
import io.github.baylorpaul.webauthn4jmicronaut.entity.User;
import io.github.baylorpaul.webauthn4jmicronaut.security.PasskeyConfigurationProperties;
import io.github.baylorpaul.webauthn4jmicronaut.security.jwt.TestCredentialsUtil;
import io.github.baylorpaul.webauthn4jmicronaut.security.model.LoginResponse;
import io.github.baylorpaul.webauthn4jmicronaut.security.passkey.model.PasskeyCredAndUserHandle;
import io.github.baylorpaul.webauthn4jmicronaut.service.JsonService;
import io.github.baylorpaul.webauthn4jmicronaut.service.mail.MockEmailService;
import io.github.baylorpaul.webauthn4jmicronaut.service.mail.template.PasskeyAdditionLinkEmailTemplate;
import io.github.baylorpaul.webauthn4jmicronaut.util.JsonApiTestUtil;
import io.github.baylorpaul.webauthn4jmicronaut.util.PasskeyTestUtil;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.*;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.json.JsonMapper;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.annotation.Nullable;
import jakarta.inject.Inject;
import jakarta.validation.constraints.NotNull;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Consumer;

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
	private MockEmailService mockEmailService;

	@Inject
	private JsonMapper jsonMapper;

	@Inject
	private ApplicationConfigurationProperties appProps;

	@Inject
	private PasskeyConfigurationProperties passkeyConfigurationProps;

	@Inject
	private JsonService jsonService;

	@BeforeEach
	public void init() {
		this.testCreds = testCredentialsUtil.createTestCredsWithPassword();
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
		PublicKeyCredentialCreationOptionsSessionDto res = genRegOpts(email);

		PasskeyCredAndUserHandle credAndUserHandle = generatePasskeyCredWithUserHandle(res);
		AttestedCredentialData attestedCredentialData = credAndUserHandle.attestedCredentialDataIncludingPrivateKey();

		PasskeyCredentials pc = registerPasskey(res, attestedCredentialData);

		PublicKeyCredentialRequestOptionsSessionDto dto = generateAuthOpts();

		assertAuthenticationVerificationSucceeds(dto, credAndUserHandle);
	}

	@Test
	public void testVerifyAuthWithSignatureFromDifferentKey() {
		final String email = "brand-new-user13989@gmail.com";
		PublicKeyCredentialCreationOptionsSessionDto res = genRegOpts(email);

		PasskeyCredAndUserHandle credAndUserHandle = generatePasskeyCredWithUserHandle(res);
		AttestedCredentialData attestedCredentialData = credAndUserHandle.attestedCredentialDataIncludingPrivateKey();
		COSEKey coseKey = attestedCredentialData.getCOSEKey();

		PasskeyCredentials pc = registerPasskey(res, attestedCredentialData);

		PublicKeyCredentialRequestOptionsSessionDto dto = generateAuthOpts();

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

	private void assertAuthenticationVerificationSucceeds(
			PublicKeyCredentialRequestOptionsSessionDto dto, PasskeyCredAndUserHandle credAndUserHandle
	) {
		Map<String, Object> authenticationResponse = PasskeyTestUtil.generatePasskeyAuthenticationResponse(
				passkeyConfigurationProps, dto.getPublicKeyCredentialRequestOptions(), credAndUserHandle, null
		);

		// Now log in
		LoginResponse loginResponse = verifyAuthentication(
				dto.getChallengeSessionId(),
				authenticationResponse,
				"/passkeys/methods/verifyAuthenticationForAccessTokenResponse",
				null,
				LoginResponse.class
		);

		// The JWT username is the user ID
		long userId = Long.parseLong(loginResponse.getUsername());
		Assertions.assertTrue(userId > 0L);
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
			verifyAuthentication(
					dto.getChallengeSessionId(),
					authenticationResponse,
					"/passkeys/methods/verifyAuthenticationForAccessTokenResponse",
					null,
					LoginResponse.class
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
		PublicKeyCredentialCreationOptionsSessionDto res = genRegOpts(email);

		PasskeyCredAndUserHandle credAndUserHandle = generatePasskeyCredWithUserHandle(res);
		AttestedCredentialData attestedCredentialData = credAndUserHandle.attestedCredentialDataIncludingPrivateKey();

		PasskeyCredentials pc = registerPasskey(res, attestedCredentialData);

		PublicKeyCredentialRequestOptionsSessionDto dto = generateAuthOpts();

		Map<String, Object> authenticationResponse = PasskeyTestUtil.generatePasskeyAuthenticationResponse(
				passkeyConfigurationProps, dto.getPublicKeyCredentialRequestOptions(), credAndUserHandle, null
		);

		// Get a short-lived confirmation token that confirms user access to take a protected action, such as
		// associating a federated login for the first time with the user's account
		String confirmationToken = verifyAuthentication(
				dto.getChallengeSessionId(),
				authenticationResponse,
				"/passkeys/methods/verifyAuthenticationForConfirmationTokenResponse",
				null,
				String.class
		);

		// TODO use the "confirmationToken" to take a protected action while not otherwise authenticated, such as
		//  linking a federated login first the first time to an existing user account
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
		PublicKeyCredentialCreationOptionsSessionDto res = genRegOpts(email);

		AttestedCredentialData attestedCredentialData = PasskeyTestUtil.generateAttestedCredentialData(true);

		// Don't use the provided challenge. Override it to something else
		try {
			Challenge challengeOverride = new DefaultChallenge();
			Map<String, Object> registrationResponseWithWrongChallenge = PasskeyTestUtil.generatePasskeyRegistrationResponse(
					passkeyConfigurationProps, res.getPublicKeyCredentialCreationOptions(), challengeOverride, attestedCredentialData
			);
			verifyRegistration(res.getChallengeSessionId(), registrationResponseWithWrongChallenge);
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
			verifyRegistration(res.getChallengeSessionId(), registrationResponse);
			Assertions.fail("Expected the registration to fail because the challenge was previously discarded");
		} catch (HttpClientResponseException e) {
			JsonApiTestUtil.assertJsonApiErrorResponse(e, HttpStatus.NOT_FOUND,
					"invalid or expired challenge session"
			);
		}
	}

	private PublicKeyCredentialCreationOptionsSessionDto genRegOpts(String email) {
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

	private PasskeyCredentials verifyRegistration(UUID challengeSessionId, Map<String, Object> registrationResponse) {
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

	private <T> T verifyAuthentication(
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

	/**
	 * Test the "lost my passkey" flow. This uses ConfirmationType.PASSKEY_ADDITION.
	 * Generate passkey registration options for an existing, yet unauthenticated, account via confirmation token.
	 */
	@Test
	public void testGenPasskeyRegOptsViaTokenForExistingAccount() throws URISyntaxException {
		final User user = testCredentialsUtil.createUser("brand-new-user48417@gmail.com");

		// The URI where the token will be added. As opposed to "password reset" emails, etc., the web app
		// implements this webpage because the passkey "Relying Party" (RP) ID and origin URL must match the web app.
		final String addPasskeyUriPathWithoutToken = "/login/addPasskeyViaToken";

		// This should work whether the user's email is verified or not
		PasskeyAdditionLinkEmailTemplate template = sendPasskeyResetLinkEmail(user.getEmail(), addPasskeyUriPathWithoutToken);
		Assertions.assertNotNull(template);

		PublicKeyCredentialCreationOptionsSessionDto res = generateRegistrationOptionsForExistingAccount(
				user, addPasskeyUriPathWithoutToken, template.getWebPasskeyAdditionUrl()
		);

		// Should not be able to generate passkey registration options a second time with the same token
		try {
			generateRegistrationOptionsForExistingAccount(
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
		PasskeyCredentials pc = verifyRegistration(res.getChallengeSessionId(), registrationResponse);
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

	private PublicKeyCredentialCreationOptionsSessionDto generateRegistrationOptionsForExistingAccount(
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

	/**
	 * Add a passkey to an existing account that is already authenticated, using password credentials to re-verify
	 * access. The user may re-verify via one of multiple authentication methods, but this test only uses the password
	 * option.
	 */
	@Test
	public void testRegisterNewPasskeyAsAuthenticatedUserUsingAPasswordToConfirmAccess() {
		UserVerificationDto userVerificationDto = UserVerificationDto.builder()
				.platform("web")
				.jwtPasskeyAccessVerifiedToken(null)
				.password(TestCredentialsUtil.TEST_PASSWORD)
				.build();

		AttestedCredentialData attestedCredentialData = PasskeyTestUtil.generateAttestedCredentialData(true);
		registerPasskeyWithConfirmedUserAccess(userVerificationDto, attestedCredentialData);
	}

	/**
	 * Add a passkey to an existing account that is already authenticated, using pre-existing passkey credentials to
	 * re-verify access. The user may re-verify via one of multiple authentication methods, but this test only uses the
	 * passkey option. When the user re-authenticates with a passkey, the server will generate a short-lived token. That
	 * token is used to confirm access when creating a new passkey. This uses ConfirmationType.PASSKEY_ACCESS_VERIFIED.
	 */
	@Test
	public void testRegisterNewPasskeyAsAuthenticatedUserUsingAPreExistingPasskeyToConfirmAccess() {
		// First, make sure we have a passkey, with which we'll re-verify access to the user's account
		PasskeyCredAndUserHandle credAndUserHandle = testCredentialsUtil.createAndPersistPasskeyRecordByUserId(testCreds.userId());

		// Re-verify user access. We'll use that confirmation token to generate passkey registration options.
		// Those registration options will subsequently be used to add another passkey to the user's account.
		UserVerificationDto userVerificationDto = reVerifyUserAccessViaPasskey(credAndUserHandle);

		// Making a separate passkey, so make new AttestedCredentialData.
		// Don't reuse credAndUserHandle.attestedCredentialDataIncludingPrivateKey().
		// Even if we tried to reuse it, we'd get a conflict due to a reuse of a credential ID.
		AttestedCredentialData newAttestedCredentialData = PasskeyTestUtil.generateAttestedCredentialData(true);
		registerPasskeyWithConfirmedUserAccess(
				userVerificationDto, newAttestedCredentialData
		);
	}

	private void registerPasskeyWithConfirmedUserAccess(
			@NonNull UserVerificationDto userVerificationDto, @NonNull AttestedCredentialData attestedCredentialData
	) {
		// Generate passkey registration options that will be used to add a new passkey to the user's account.
		PublicKeyCredentialCreationOptionsSessionDto res = genRegOptsAsAuthenticatedUser(userVerificationDto);

		// Now verify the registration of a new passkey
		registerAndAssertPasskeyCredsCreatedForTestUser(res, attestedCredentialData);
	}

	@Test
	public void testConfirmationTokenReuseForGenPasskeyRegOpts() {
		PasskeyCredAndUserHandle credAndUserHandle = testCredentialsUtil.createAndPersistPasskeyRecordByUserId(testCreds.userId());
		UserVerificationDto userVerificationDto = reVerifyUserAccessViaPasskey(credAndUserHandle);

		// The first attempt to use the confirmation token should succeed
		PublicKeyCredentialCreationOptionsSessionDto res1 = genRegOptsAsAuthenticatedUser(userVerificationDto);

		// Making a separate passkey, so make new AttestedCredentialData.
		// Don't reuse credAndUserHandle.attestedCredentialDataIncludingPrivateKey().
		// Even if we tried to reuse it, we'd get a conflict due to a reuse of a credential ID.
		AttestedCredentialData newAttestedCredentialData = PasskeyTestUtil.generateAttestedCredentialData(true);

		// The second attempt should fail due to token reuse
		try {
			genRegOptsAsAuthenticatedUser(userVerificationDto);
			Assertions.fail("Expected to get a 'Gone' response");
		} catch (HttpClientResponseException e) {
			JsonApiTestUtil.assertJsonApiErrorResponse(e, HttpStatus.GONE,
					"Confirmation token has already been utilized"
			);
		}

		// The original options are still valid
		registerAndAssertPasskeyCredsCreatedForTestUser(res1, newAttestedCredentialData);

		// Now the challenge is discarded, so the original options are no longer valid
		try {
			registerAndAssertPasskeyCredsCreatedForTestUser(res1, newAttestedCredentialData);
			Assertions.fail("Expected to get a 'Not Found' response");
		} catch (HttpClientResponseException e) {
			JsonApiTestUtil.assertJsonApiErrorResponse(e, HttpStatus.NOT_FOUND,
					"invalid or expired challenge session"
			);
		}
	}

	private PublicKeyCredentialCreationOptionsSessionDto genRegOptsAsAuthenticatedUser(UserVerificationDto userVerificationDto) {
		String userVerificationJSON = jsonService.toJson(userVerificationDto);

		MutableHttpRequest<?> req = HttpRequest.POST(
				"/passkeys/methods/generateRegistrationOptionsAsAuthenticatedUser",
				userVerificationJSON
		).bearerAuth(testCreds.accessToken());

		HttpResponse<PublicKeyCredentialCreationOptionsSessionDto> rsp = client.toBlocking().exchange(
				req,
				PublicKeyCredentialCreationOptionsSessionDto.class
		);
		Assertions.assertEquals(HttpStatus.OK, rsp.getStatus());

		PublicKeyCredentialCreationOptionsSessionDto res = rsp.body();
		assertValidPublicKeyCredentialCreationOptionsSessionDto(
				res, TestCredentialsUtil.TEST_EMAIL, TestCredentialsUtil.TEST_NAME
		);

		return res;
	}

	/**
	 * Register a new passkey
	 */
	private PasskeyCredentials registerPasskey(
			PublicKeyCredentialCreationOptionsSessionDto res, AttestedCredentialData attestedCredentialData
	) {
		Map<String, Object> registrationResponse = PasskeyTestUtil.generatePasskeyRegistrationResponse(
				passkeyConfigurationProps, res.getPublicKeyCredentialCreationOptions(), null, attestedCredentialData
		);
		PasskeyCredentials pc = verifyRegistration(res.getChallengeSessionId(), registrationResponse);
		// Verify the user exists and has a passkey by checking if there is a user ID
		Assertions.assertTrue(pc.getUser().getId() > 0L);
		return pc;
	}

	/**
	 * Register a new passkey and verify it for the test user
	 */
	private void registerAndAssertPasskeyCredsCreatedForTestUser(
			PublicKeyCredentialCreationOptionsSessionDto res, AttestedCredentialData attestedCredentialData
	) {
		PasskeyCredentials pc = registerPasskey(res, attestedCredentialData);
		Assertions.assertEquals(testCreds.userId(), pc.getUser().getId());
	}

	/**
	 * Re-verify user access as an authenticated user in exchange for a short-lived confirmation token that can be used
	 * to take protected actions. E.g. adding an integration token, changing a user's password, or adding another
	 * passkey to the user's account.
	 */
	private UserVerificationDto reVerifyUserAccessViaPasskey(PasskeyCredAndUserHandle credAndUserHandle) {
		// Re-confirm the user has access to the account by re-signing in via passkey in exchange for a short-lived
		// token. This method expects the user to already be signed in. This is NOT a "lost my passkey" method.
		String passkeyAccessVerifiedToken = reVerifyPasskeyAuthenticationForConfirmationToken(credAndUserHandle);
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
			@NotNull PasskeyCredAndUserHandle credAndUserHandle
	) {
		PublicKeyCredentialRequestOptionsSessionDto dto = generateAuthOptsAsAuthenticatedUser();

		Map<String, Object> authenticationResponse = PasskeyTestUtil.generatePasskeyAuthenticationResponse(
				passkeyConfigurationProps, dto.getPublicKeyCredentialRequestOptions(), credAndUserHandle, null
		);

		return verifyAuthentication(
				dto.getChallengeSessionId(),
				authenticationResponse,
				"/passkeys/methods/verifyAuthenticationAsAuthenticatedUserForConfirmationTokenResponse",
				req -> req.bearerAuth(testCreds.accessToken()),
				String.class
		);
	}

	private PublicKeyCredentialRequestOptionsSessionDto generateAuthOpts() {
		HttpRequest<?> request = HttpRequest.GET("/passkeys/methods/generateAuthenticationOptions");
		HttpResponse<PublicKeyCredentialRequestOptionsSessionDto> rsp = client.toBlocking().exchange(
				request,
				PublicKeyCredentialRequestOptionsSessionDto.class
		);
		PublicKeyCredentialRequestOptionsSessionDto dto = rsp.body();
		Assertions.assertNotNull(dto);
		return dto;
	}

	private PublicKeyCredentialRequestOptionsSessionDto generateAuthOptsAsAuthenticatedUser() {
		HttpRequest<?> request = HttpRequest.GET("/passkeys/methods/generateAuthenticationOptionsAsAuthenticatedUser")
				.bearerAuth(testCreds.accessToken());
		HttpResponse<PublicKeyCredentialRequestOptionsSessionDto> rsp = client.toBlocking().exchange(
				request,
				PublicKeyCredentialRequestOptionsSessionDto.class
		);
		PublicKeyCredentialRequestOptionsSessionDto dto = rsp.body();
		Assertions.assertNotNull(dto);
		return dto;
	}

	@Test
	public void testCreateUserWithPasskeyAndRetrieveUserRecord() {
		final String email = "brand-new-user42578@gmail.com";
		TestCredentialsUtil.TestCreds creds = testCredentialsUtil.createUserAndAccessTokenWithPasskeyCreds(email);

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
		testCredentialsUtil.createAndPersistPasskeyRecordByUserId(testCreds.userId());

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
		testCredentialsUtil.createAndPersistPasskeyRecordByUserId(testCreds.userId());

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

		PasskeyCredentials pc = readAndAssertPasskeyCredentials(res.getData());
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

		PasskeyCredentials pc = readAndAssertPasskeyCredentials(res.getData());
		Assertions.assertEquals(testCreds.userId(), pc.getUser().getId());
		return pc;
	}

	private PasskeyCredentials readAndAssertPasskeyCredentials(JsonApiResource data) {
		PasskeyCredentials pc = JsonApiUtil.readResourceWithId(jsonMapper, data, PasskeyCredentials.class)
				.orElseThrow(() -> new RuntimeException("Expected to find passkey credentials"));
		Assertions.assertNotNull(pc);
		Assertions.assertTrue(pc.getId() > 0L);
		Assertions.assertNotNull(pc.getUser());
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
