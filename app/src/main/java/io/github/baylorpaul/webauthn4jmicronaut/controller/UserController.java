package io.github.baylorpaul.webauthn4jmicronaut.controller;

import io.github.baylorpaul.micronautjsonapi.identifiable.JsonApiResourceable;
import io.github.baylorpaul.micronautjsonapi.model.JsonApiObject;
import io.github.baylorpaul.micronautjsonapi.model.JsonApiResource;
import io.github.baylorpaul.micronautjsonapi.model.JsonApiTopLevelResource;
import io.github.baylorpaul.micronautjsonapi.util.JsonApiUtil;
import io.github.baylorpaul.webauthn4jmicronaut.repo.UserRepository;
import io.github.baylorpaul.webauthn4jmicronaut.rest.UserRestService;
import io.github.baylorpaul.webauthn4jmicronaut.security.SecurityUtil;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Patch;
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

	@Inject
	private UserRestService userRestService;

	@Secured(SecurityRule.IS_AUTHENTICATED)
	@Get("/me")
	public Optional<JsonApiTopLevelResource> showMe(Principal principal) {
		long id = SecurityUtil.requireUserId(principal);
		return userRepo.findById(id)
				.map(JsonApiResourceable::toTopLevelResource);
	}

	@Secured(SecurityRule.IS_AUTHENTICATED)
	@Patch("/{id}")
	public Optional<JsonApiTopLevelResource> update(long id, Principal principal, @Body JsonApiObject<JsonApiResource> body) {
		return JsonApiUtil.readAndValidateLongId(body, id)
				.map(bodyId -> bodyId.longValue() == SecurityUtil.requireUserId(principal) ? bodyId : null)
				.flatMap(bodyId -> userRepo.findById(bodyId))
				.map(user -> userRestService.updateUser(user, body.getData()))
				.map(JsonApiResourceable::toTopLevelResource);
	}
}
