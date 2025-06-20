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
import io.github.baylorpaul.webauthn4jmicronaut.security.PasskeyConfigurationProperties;
import io.github.baylorpaul.webauthn4jmicronaut.security.PasskeyService;
import io.github.baylorpaul.webauthn4jmicronaut.security.model.LoginResponse;
import io.github.baylorpaul.webauthn4jmicronaut.security.passkey.model.PasskeyCredAndUserHandle;
import io.github.baylorpaul.webauthn4jmicronaut.service.JsonService;
import io.github.baylorpaul.webauthn4jmicronaut.util.EmailUtil;
import io.github.baylorpaul.webauthn4jmicronaut.util.PasskeyTestUtil;
import io.github.baylorpaul.webauthn4jmicronaut.util.PasswordUtil;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.json.JsonMapper;
import io.micronaut.security.authentication.UsernamePasswordCredentials;
import io.micronaut.security.token.render.BearerAccessRefreshToken;
import io.micronaut.transaction.TransactionDefinition;
import io.micronaut.transaction.annotation.Transactional;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Assertions;

import java.util.Map;

@Singleton
public class TestCredentialsUtil {

	public static final String TEST_EMAIL = "mrwilliams@example.com";
	public static final String TEST_NAME = "Mister Williams";
	public static final String TEST_PASSWORD = PasswordUtil.FAKE_PASSWORD;

	/** Credentials for a test */
	public record TestCreds(long userId, String accessToken) {}

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
	@Client("/")
	private HttpClient client;

	@Inject
	private UserRestService userRestService;

	@Transactional(propagation = TransactionDefinition.Propagation.REQUIRES_NEW)
	public @NonNull User createUser(String email) {
		return userRestService.createUser(email, null, null);
	}

	/**
	 * @return the user ID
	 */
	public long saveTestUserIfNotExists() {
		String email = EmailUtil.formatEmailAddress(TEST_EMAIL);
		userRepo.saveUserIfNotExists(email, TEST_NAME);
		long userId = userRepo.findByEmail(email).map(User::getId).orElse(-1L).longValue();
		Assertions.assertTrue(userId > 0L);
		return userId;
	}

	public TestCreds createTestCredsWithPassword() {
		long userId = saveTestUserIfNotExists();
		String accessToken = createAccessTokenWithPassword(TEST_EMAIL, TEST_PASSWORD);
		return new TestCreds(userId, accessToken);
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
	 * Create a user, add passkey credentials to that user, and then login with those passkey credentials to get an access token
	 */
	public TestCreds createUserAndAccessTokenWithPasskeyCreds(String email) {

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
		HttpResponse<LoginResponse> authRsp = client.toBlocking().exchange(
				HttpRequest.POST(
								"/passkeys/methods/verifyAuthenticationForAccessTokenResponse",
								jsonService.toJson(authenticationResponse)
						)
						.header("X-Challenge-Session-ID", dto.getChallengeSessionId().toString()),
				LoginResponse.class
		);
		LoginResponse lr = authRsp.body();
		Assertions.assertNotNull(lr);
		final long userId = Long.parseLong(lr.getUsername());
		final String accessToken = lr.getAccessToken();

		return new TestCreds(userId, accessToken);
	}

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
