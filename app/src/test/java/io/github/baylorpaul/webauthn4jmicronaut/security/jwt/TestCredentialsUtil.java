package io.github.baylorpaul.webauthn4jmicronaut.security.jwt;

import io.github.baylorpaul.webauthn4jmicronaut.entity.User;
import io.github.baylorpaul.webauthn4jmicronaut.repo.UserRepository;
import io.github.baylorpaul.webauthn4jmicronaut.util.EmailUtil;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.security.authentication.UsernamePasswordCredentials;
import io.micronaut.security.token.render.BearerAccessRefreshToken;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

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
}
