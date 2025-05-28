package io.github.baylorpaul.webauthn4jmicronaut.controller;

import io.github.baylorpaul.micronautjsonapi.identifiable.JsonApiResourceable;
import io.github.baylorpaul.micronautjsonapi.model.JsonApiTopLevelResource;
import io.github.baylorpaul.webauthn4jmicronaut.repo.UserRepository;
import io.github.baylorpaul.webauthn4jmicronaut.security.SecurityUtil;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import jakarta.inject.Inject;

import java.security.Principal;
import java.util.Optional;

@ExecuteOn(TaskExecutors.IO)
@Controller("/users")
public class UserController {

	@Inject
	private UserRepository userRepo;

	@Secured(SecurityRule.IS_AUTHENTICATED)
	@Get("/me")
	public Optional<JsonApiTopLevelResource> showMe(Principal principal) {
		long id = SecurityUtil.requireUserId(principal);
		return userRepo.findById(id)
				.map(JsonApiResourceable::toTopLevelResource);
	}
}
