package io.github.baylorpaul.webauthn4jmicronaut.security.jwt;

import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import io.github.baylorpaul.micronautjsonapi.model.JsonApiTopLevelResource;
import io.github.baylorpaul.webauthn4jmicronaut.dto.api.submission.UserVerificationDto;
import io.github.baylorpaul.webauthn4jmicronaut.entity.User;
import io.github.baylorpaul.webauthn4jmicronaut.repo.UserRepository;
import io.github.baylorpaul.webauthn4jmicronaut.rest.UserRestService;
import io.github.baylorpaul.webauthn4jmicronaut.security.PasskeyConfigurationProperties;
import io.github.baylorpaul.webauthn4jmicronaut.security.PasskeyService;
import io.github.baylorpaul.webauthn4jmicronaut.security.passkey.model.PasskeyCredAndUserHandle;
import io.github.baylorpaul.webauthn4jmicronaut.util.EmailUtil;
import io.github.baylorpaul.webauthn4jmicronaut.util.PasskeyTestUtil;
import io.github.baylorpaul.webauthn4jmicronaut.util.PasswordUtil;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.authentication.UsernamePasswordCredentials;
import io.micronaut.security.token.render.BearerAccessRefreshToken;
import io.micronaut.transaction.TransactionDefinition;
import io.micronaut.transaction.annotation.Transactional;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Assertions;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@Singleton
public class TestCredentialsUtil {

	public static final String TEST_EMAIL = "mrwilliams@example.com";
	public static final String TEST_NAME = "Mister Williams";
	public static final String TEST_PASSWORD = PasswordUtil.FAKE_PASSWORD;

	/** Credentials for a test */
	public record TestCreds(long userId, String accessToken) {}

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

	public TestCreds createTestCreds() {
		String email = EmailUtil.formatEmailAddress(TEST_EMAIL);
		userRepo.saveUserIfNotExists(email, TEST_NAME);
		long userId = userRepo.findByEmail(email).map(User::getId).orElse(-1L).longValue();
		assertNotEquals(-1L, userId);

		String accessToken = createAccessToken(TEST_EMAIL, TEST_PASSWORD);
		return new TestCreds(userId, accessToken);
	}

	public String createAccessToken(String email, String password) {
		UsernamePasswordCredentials creds = new UsernamePasswordCredentials(email, password);
		HttpRequest<?> request = HttpRequest.POST("/login", creds);
		BearerAccessRefreshToken rsp = client.toBlocking().retrieve(request, BearerAccessRefreshToken.class);
		String accessToken = rsp.getAccessToken();
		assertNotNull(accessToken);

		return accessToken;
	}

	@Transactional(propagation = TransactionDefinition.Propagation.REQUIRES_NEW)
	public @NonNull PasskeyCredAndUserHandle createPasskeyRecordByUserId(long userId) {
		String userHandleBase64Url = passkeyService.findUserHandleBase64Url(String.valueOf(userId), true);
		return createPasskeyRecord(userHandleBase64Url);
	}

	@Transactional(propagation = TransactionDefinition.Propagation.REQUIRES_NEW)
	public @NonNull PasskeyCredAndUserHandle createPasskeyRecordByUserHandleBase64Url(String userHandleBase64Url) {
		return createPasskeyRecord(userHandleBase64Url);
	}

	private @NonNull PasskeyCredAndUserHandle createPasskeyRecord(String userHandleBase64Url) {
		String originUrl = passkeyProps.getOriginUrl();
		boolean includePrivateKey = true;
		CredentialRecord credIncludingPrivateKey = PasskeyTestUtil.generateCredentialRecord(
				originUrl,
				new DefaultChallenge(),
				includePrivateKey
		);

		// Even though we need the private key in PasskeyCredAndUserHandle (for the frontend portion of the tests),
		// make sure we're not saving the private key on the backend (or even sending it to the backend)
		CredentialRecord credWithoutPrivateKey = PasskeyTestUtil.cloneCredentialRecordWithoutPrivateKey(
				credIncludingPrivateKey
		);

		Assertions.assertNotNull(credIncludingPrivateKey.getAttestedCredentialData().getCOSEKey().getPrivateKey());
		Assertions.assertNull(credWithoutPrivateKey.getAttestedCredentialData().getCOSEKey().getPrivateKey());

		passkeyService.saveCredential(userHandleBase64Url, credWithoutPrivateKey);

		return new PasskeyCredAndUserHandle(
				credIncludingPrivateKey.getAttestedCredentialData(),
				userHandleBase64Url
		);
	}
}
