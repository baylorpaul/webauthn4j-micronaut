package io.github.baylorpaul.webauthn4jmicronaut.security.jwt;

import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.util.Base64UrlUtil;
import io.github.baylorpaul.webauthn4jmicronaut.entity.PasskeyUserHandle;
import io.github.baylorpaul.webauthn4jmicronaut.entity.User;
import io.github.baylorpaul.webauthn4jmicronaut.repo.PasskeyUserHandleRepository;
import io.github.baylorpaul.webauthn4jmicronaut.repo.UserRepository;
import io.github.baylorpaul.webauthn4jmicronaut.security.PasskeyConfigurationProperties;
import io.github.baylorpaul.webauthn4jmicronaut.security.PasskeyService;
import io.github.baylorpaul.webauthn4jmicronaut.util.EmailUtil;
import io.github.baylorpaul.webauthn4jmicronaut.util.PasskeyTestUtil;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.authentication.UsernamePasswordCredentials;
import io.micronaut.security.token.render.BearerAccessRefreshToken;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@Singleton
public class TestCredentialsUtil {

	public static final String TEST_EMAIL = "mrwilliams@example.com";
	public static final String TEST_NAME = "Mister Williams";
	public static final String TEST_PASSWORD = "dream-satchel-tortilla";

	/** Credentials for a test */
	public record TestCreds(long userId, String accessToken) {}

	@Inject
	private UserRepository userRepo;

	@Inject
	private PasskeyConfigurationProperties passkeyProps;

	@Inject
	private PasskeyUserHandleRepository passkeyUserHandleRepo;

	@Inject
	private PasskeyService passkeyService;

	@Inject
	@Client("/")
	private HttpClient client;

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

	public void createPasskeyRecord(long userId) {
		PasskeyUserHandle passkeyUserHandle = createPasskeyUserHandle(userId);
		String userHandleBase64 = passkeyUserHandle.getId();

		String originUrl = passkeyProps.getOriginUrl();
		CredentialRecord cred = PasskeyTestUtil.buildFakeCredentialRecord(
				originUrl,
				new DefaultChallenge()
		);

		passkeyService.saveCredential(userHandleBase64, cred);
	}

	private PasskeyUserHandle createPasskeyUserHandle(long userId) {
		SecureRandom random = new SecureRandom();
		byte[] userHandle = new byte[64];
		random.nextBytes(userHandle);

		User userRef = User.builder().id(userId).build();

		return passkeyUserHandleRepo.save(PasskeyUserHandle.builder()
				.id(Base64UrlUtil.encodeToString(userHandle))
				.user(userRef)
				.build());
	}
}
