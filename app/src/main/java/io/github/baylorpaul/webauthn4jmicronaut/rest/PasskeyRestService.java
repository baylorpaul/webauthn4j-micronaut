package io.github.baylorpaul.webauthn4jmicronaut.rest;

import io.github.baylorpaul.micronautjsonapi.model.JsonApiResource;
import io.github.baylorpaul.micronautjsonapi.util.JsonApiUtil;
import io.github.baylorpaul.webauthn4jmicronaut.entity.PasskeyCredentials;
import io.github.baylorpaul.webauthn4jmicronaut.repo.PasskeyCredentialsRepository;
import io.github.baylorpaul.webauthn4jmicronaut.util.Utility;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.exceptions.HttpStatusException;
import io.micronaut.json.JsonMapper;
import io.micronaut.transaction.annotation.Transactional;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

@Singleton
@Transactional
public class PasskeyRestService {

	private static final int MAX_CHARS_PASSKEY_NAME = 20;

	@Inject
	private PasskeyCredentialsRepository passkeyCredentialsRepo;

	@Inject
	private JsonMapper jsonMapper;

	public PasskeyCredentials updatePasskey(@NonNull PasskeyCredentials pc, @NonNull JsonApiResource res) {
		if (res.getAttributes() != null) {
			PasskeyCredentials dto = JsonApiUtil.readValue(jsonMapper, res.getAttributes(), PasskeyCredentials.class);
			for (String key : res.getAttributes().keySet()) {
				switch (key) {
					case "passkeyName":
						if (Utility.unNull(dto.getPasskeyName()).length() > MAX_CHARS_PASSKEY_NAME) {
							throw new HttpStatusException(HttpStatus.BAD_REQUEST, "Field too long (max=" + MAX_CHARS_PASSKEY_NAME + "): " + key);
						}
						pc.setPasskeyName(dto.getPasskeyName());
						break;
					default:
						throw new HttpStatusException(HttpStatus.BAD_REQUEST, "Unexpected field: " + key);
				}
			}
			pc = passkeyCredentialsRepo.update(pc);
		}
		if (res.getRelationships() != null) {
			throw new HttpStatusException(HttpStatus.FORBIDDEN, "Relationship updates not supported for this record");
		}
		return pc;
	}
}
