package io.github.baylorpaul.webauthn4jmicronaut.security.jwt;

import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.util.Base64UrlUtil;
import io.github.baylorpaul.micronautjsonapi.model.JsonApiTopLevelResource;
import io.github.baylorpaul.micronautjsonapi.util.JsonApiUtil;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.PublicKeyCredentialCreationOptionsSessionDto;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.PublicKeyCredentialRequestOptionsSessionDto;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.submission.UserVerificationDto;
import io.github.baylorpaul.webauthn4jmicronaut.entity.PasskeyCredentials;
import io.github.baylorpaul.webauthn4jmicronaut.entity.User;
import io.github.baylorpaul.webauthn4jmicronaut.repo.UserRepository;
import io.github.baylorpaul.webauthn4jmicronaut.rest.UserRestService;
import io.github.baylorpaul.webauthn4jmicronaut.security.AuthenticationProviderForPreVerifiedCredentials;
import io.github.baylorpaul.webauthn4jmicronaut.security.PasskeyConfigurationProperties;
import io.github.baylorpaul.webauthn4jmicronaut.security.PasskeyService;
import io.github.baylorpaul.webauthn4jmicronaut.security.model.AuthenticationUserInfo;
import io.github.baylorpaul.webauthn4jmicronaut.security.passkey.model.PasskeyCredAndUserHandle;
import io.github.baylorpaul.webauthn4jmicronaut.service.JsonService;
import io.github.baylorpaul.webauthn4jmicronaut.util.ApiUtil;
import io.github.baylorpaul.webauthn4jmicronaut.util.EmailUtil;
import io.github.baylorpaul.webauthn4jmicronaut.util.PasskeyTestUtil;
import io.github.baylorpaul.webauthn4jmicronaut.util.PasswordUtil;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.exceptions.HttpStatusException;
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.json.JsonMapper;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.UsernamePasswordCredentials;
import io.micronaut.security.handlers.LoginHandler;
import io.micronaut.security.token.render.BearerAccessRefreshToken;
import io.micronaut.transaction.TransactionDefinition;
import io.micronaut.transaction.annotation.Transactional;
import jakarta.annotation.Nullable;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.validation.constraints.NotBlank;
import org.junit.jupiter.api.Assertions;

import java.security.SecureRandom;
import java.util.Map;

@Singleton
public class TestCredentialsUtil {

	public static final String TEST_EMAIL = "mrwilliams@example.com";
	public static final String TEST_NAME = "Mister Williams";
	public static final String TEST_PASSWORD = PasswordUtil.FAKE_PASSWORD;

	public record UserPasskeyInfo(long userId, PasskeyCredAndUserHandle passkeyCredAndUserHandle) {}

	/** Credentials for a test */
	public record TestCreds(long userId, String accessToken, @Nullable PasskeyCredAndUserHandle passkeyCredAndUserHandle) {}

	@Inject
	private JsonService jsonService;

	@Inject
	private JsonMapper jsonMapper;

	@Inject
	private UserRepository userRepo;

	@Inject
	private PasskeyConfigurationProperties passkeyProps;

	@Inject
	private PasskeyService<JsonApiTopLevelResource, UserVerificationDto> passkeyService;

	@Inject
	private LoginHandler<HttpRequest<?>, MutableHttpResponse<BearerAccessRefreshToken>> loginHandler;

	@Inject
	@Client("/")
	private HttpClient client;

	@Inject
	private UserRestService userRestService;

	public static @NonNull String generateRandomEmail() {
		return "generated-user" + new SecureRandom().nextInt() + "@example.com";
	}

	@Transactional(propagation = TransactionDefinition.Propagation.REQUIRES_NEW)
	public @NonNull User createUser(String email) {
		return userRestService.createUser(email, null, null);
	}

	/**
	 * @return the user ID
	 */
	public long saveTestUserIfNotExists() {
		return saveUserIfNotExists(TEST_EMAIL, TEST_NAME);
	}

	/**
	 * @return the user ID
	 */
	private long saveUserIfNotExists(@NonNull @NotBlank String email, @NonNull @NotBlank String name) {
		email = EmailUtil.formatEmailAddress(email);
		userRepo.saveUserIfNotExists(email, name);
		long userId = userRepo.findByEmail(email).map(User::getId).orElse(-1L).longValue();
		Assertions.assertTrue(userId > 0L);
		return userId;
	}

	public TestCreds createTestCredsWithPassword() {
		long userId = saveTestUserIfNotExists();
		String accessToken = createAccessTokenWithPassword(TEST_EMAIL, TEST_PASSWORD);
		return new TestCreds(userId, accessToken, null);
	}

	public User findUser(UserPasskeyInfo userPasskeyInfo) {
		return userRepo.findById(userPasskeyInfo.userId())
				.orElseThrow(() -> new HttpStatusException(HttpStatus.NOT_FOUND, "User not found"));
	}

	public User findUser(TestCreds testCreds) {
		return userRepo.findById(testCreds.userId())
				.orElseThrow(() -> new HttpStatusException(HttpStatus.NOT_FOUND, "User not found"));
	}

	public String createAccessTokenWithPassword(String email, String password) {
		UsernamePasswordCredentials creds = new UsernamePasswordCredentials(email, password);
		HttpRequest<?> request = HttpRequest.POST("/login", creds);
		BearerAccessRefreshToken rsp = client.toBlocking().retrieve(request, BearerAccessRefreshToken.class);
		String accessToken = rsp.getAccessToken();
		Assertions.assertNotNull(accessToken);

		return accessToken;
	}

	/**
	 * With API calls (not direct service calls), create a user, add passkey credentials to that user, and then login
	 * with those passkey credentials to get an access token
	 */
	public TestCreds createUserAndAccessTokenWithPasskeyCredsViaApiCalls(String email) {

		// Generate Passkey registration options
		HttpResponse<PublicKeyCredentialCreationOptionsSessionDto> regOptRsp = client.toBlocking().exchange(
				HttpRequest.GET(
						UriBuilder.of("/passkeys/methods/generateRegistrationOptions")
								.queryParam("uniqueNameOrEmail", email)
								//.queryParam("displayName", displayName)
								.toString()
				),
				PublicKeyCredentialCreationOptionsSessionDto.class
		);
		PublicKeyCredentialCreationOptionsSessionDto regOptDto = regOptRsp.body();
		byte[] userHandle = regOptDto.getPublicKeyCredentialCreationOptions().getUser().getId();
		String userHandleBase64Url = Base64UrlUtil.encodeToString(userHandle);

		// Generate a credential ID and key pair
		PasskeyCredAndUserHandle credAndUserHandle = generatePasskeyCredAndUserHandle(userHandleBase64Url);

		// Simulate a call to navigator.credentials.create() in the browser/authenticator
		Map<String, Object> registrationResponse = PasskeyTestUtil.generatePasskeyRegistrationResponse(
				passkeyProps, regOptDto.getPublicKeyCredentialCreationOptions(), null,
				credAndUserHandle.attestedCredentialDataIncludingPrivateKey()
		);

		// Register a passkey
		HttpResponse<JsonApiTopLevelResource> regRsp = client.toBlocking().exchange(
				HttpRequest.POST("/passkeys/methods/verifyRegistration", jsonService.toJson(registrationResponse))
						.header("X-Challenge-Session-ID", regOptDto.getChallengeSessionId().toString()),
				JsonApiTopLevelResource.class
		);
		PasskeyCredentials pc = JsonApiUtil.readResourceWithId(jsonMapper, regRsp.body().getData(), PasskeyCredentials.class)
				.orElseThrow(() -> new RuntimeException("Expected to find passkey credentials"));

		// Generate Passkey authentication options
		HttpResponse<PublicKeyCredentialRequestOptionsSessionDto> authOptRsp = client.toBlocking().exchange(
				HttpRequest.GET("/passkeys/methods/generateAuthenticationOptions"),
				PublicKeyCredentialRequestOptionsSessionDto.class
		);
		PublicKeyCredentialRequestOptionsSessionDto dto = authOptRsp.body();

		// Simulate a call to navigator.credentials.get() in the browser/authenticator
		Map<String, Object> authenticationResponse = PasskeyTestUtil.generatePasskeyAuthenticationResponse(
				passkeyProps, dto.getPublicKeyCredentialRequestOptions(), credAndUserHandle, null
		);

		// Authenticate for an access token
		HttpResponse<BearerAccessRefreshToken> authRsp = client.toBlocking().exchange(
				HttpRequest.POST(
								"/passkeys/methods/verifyAuthenticationForAccessTokenResponse",
								jsonService.toJson(authenticationResponse)
						)
						.header("X-Challenge-Session-ID", dto.getChallengeSessionId().toString()),
				BearerAccessRefreshToken.class
		);
		BearerAccessRefreshToken bearerAccessRefreshToken = authRsp.body();
		Assertions.assertNotNull(bearerAccessRefreshToken);
		final long userId = Long.parseLong(bearerAccessRefreshToken.getUsername());
		final String accessToken = bearerAccessRefreshToken.getAccessToken();

		return new TestCreds(userId, accessToken, credAndUserHandle);
	}

	@Transactional(propagation = TransactionDefinition.Propagation.REQUIRES_NEW)
	public User createUserWithPasskeyCredsViaServiceCalls(String email) {
		TestCreds testCreds = createUserAndAccessTokenWithPasskeyCredsViaServiceCalls(email);
		return findUser(testCreds);
	}

	/**
	 * With service calls (not API calls), create a user and passkey credentials for that user. This is faster than
	 * making the API calls, and is able to skip a lot of the security requirements. That speed makes it more ideal for
	 * tests that aren't testing passkey creation, but need a passkey to exist.
	 */
	@Transactional(propagation = TransactionDefinition.Propagation.REQUIRES_NEW)
	public UserPasskeyInfo createUserPasskeyCredsViaServiceCalls(
			String email
	) {
		String formattedEmail = ApiUtil.formatAndValidateEmail(email);
		String formattedDisplayName = ApiUtil.buildAndValidateUserName(null, formattedEmail);
		long userId = saveUserIfNotExists(email, formattedDisplayName);

		// Create and save a passkey
		PasskeyCredAndUserHandle credAndUserHandle = createAndPersistPasskeyRecordByUserId(userId);
		return new UserPasskeyInfo(userId, credAndUserHandle);
	}

	/**
	 * With service calls (not API calls), create a user, add passkey credentials to that user, and then login with
	 * those passkey credentials to get an access token. This is faster than making the API calls, and is able to skip a
	 * lot of the security requirements. That speed makes it more ideal for tests that aren't testing passkey creation,
	 * but need a passkey to exist.
	 */
	@Transactional(propagation = TransactionDefinition.Propagation.REQUIRES_NEW)
	public TestCreds createUserAndAccessTokenWithPasskeyCredsViaServiceCalls(String email) {
		UserPasskeyInfo userPasskeyInfo = createUserPasskeyCredsViaServiceCalls(email);
		return authenticateForAccessToken(userPasskeyInfo);
	}

	private TestCreds authenticateForAccessToken(UserPasskeyInfo userPasskeyInfo) {
		PasskeyCredAndUserHandle credAndUserHandle = userPasskeyInfo.passkeyCredAndUserHandle();

		byte[] credentialId = credAndUserHandle.attestedCredentialDataIncludingPrivateKey().getCredentialId();
		AuthenticationUserInfo authUserInfo = passkeyService.generateAuthenticationUserInfo(credentialId);

		AuthenticationResponse authResp = AuthenticationProviderForPreVerifiedCredentials.generateAuthenticationResponse(
				authUserInfo
		);
		Authentication authentication = authResp.getAuthentication()
				.orElseThrow(() -> new RuntimeException("Unable to get authentication"));
		MutableHttpResponse<BearerAccessRefreshToken> httpResp = loginHandler.loginSuccess(authentication, null);
		BearerAccessRefreshToken loginResponse = httpResp.body();

		return new TestCreds(userPasskeyInfo.userId(), loginResponse.getAccessToken(), credAndUserHandle);
	}

	/**
	 * With service calls (not API calls), create and persist a passkey record for a user
	 */
	@Transactional(propagation = TransactionDefinition.Propagation.REQUIRES_NEW)
	public @NonNull PasskeyCredAndUserHandle createAndPersistPasskeyRecordByUserId(long userId) {
		String userHandleBase64Url = passkeyService.findUserHandleBase64Url(String.valueOf(userId), true);

		boolean includePrivateKey = true;
		AttestedCredentialData attestedCredentialDataIncludingPrivateKey = PasskeyTestUtil.generateAttestedCredentialData(includePrivateKey);

		String originUrl = passkeyProps.getOriginUrl();
		CredentialRecord credIncludingPrivateKey = PasskeyTestUtil.generateCredentialRecord(
				originUrl,
				new DefaultChallenge(),
				attestedCredentialDataIncludingPrivateKey
		);

		// Even though we need the private key in PasskeyCredAndUserHandle (for the frontend portion of the tests),
		// make sure we're not saving the private key on the backend (or even sending it to the backend)
		CredentialRecord credWithoutPrivateKey = PasskeyTestUtil.cloneCredentialRecordWithoutPrivateKey(
				credIncludingPrivateKey
		);

		Assertions.assertNotNull(credIncludingPrivateKey.getAttestedCredentialData().getCOSEKey().getPrivateKey());
		Assertions.assertNull(credWithoutPrivateKey.getAttestedCredentialData().getCOSEKey().getPrivateKey());

		passkeyService.saveCredential(userHandleBase64Url, credWithoutPrivateKey);

		return new PasskeyCredAndUserHandle(attestedCredentialDataIncludingPrivateKey, userHandleBase64Url);
	}

	public static @NonNull PasskeyCredAndUserHandle generatePasskeyCredAndUserHandle(String userHandleBase64Url) {
		AttestedCredentialData attestedCredentialDataIncludingPrivateKey = PasskeyTestUtil.generateAttestedCredentialData(true);
		return new PasskeyCredAndUserHandle(attestedCredentialDataIncludingPrivateKey, userHandleBase64Url);
	}
}
