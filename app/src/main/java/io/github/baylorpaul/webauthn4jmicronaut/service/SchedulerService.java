package io.github.baylorpaul.webauthn4jmicronaut.service;

import io.github.baylorpaul.webauthn4jmicronaut.security.PasskeyService;
import io.micronaut.scheduling.annotation.Scheduled;
import io.micronaut.transaction.annotation.Transactional;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Singleton
@Transactional
public class SchedulerService {

	private static final Logger log = LoggerFactory.getLogger(SchedulerService.class);

	@Inject
	private PasskeyService passkeyService;

	/**
	 * Remove expired challenges and unattached user handles
	 */
	@Scheduled(fixedDelay = "60m", initialDelay = "120s")
	public void passkeyCleanupJobScheduled() {

		// TODO consider a different scheduling implementation if deploying via serverless computing

		log.info("Passkey cleanup job running");
		passkeyService.deleteExpiredChallengesAndPasskeyUserHandles();
		log.info("Passkey cleanup job finished");
	}
}
