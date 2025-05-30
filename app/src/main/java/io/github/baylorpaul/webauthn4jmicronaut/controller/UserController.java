package io.github.baylorpaul.webauthn4jmicronaut.controller;

import io.github.baylorpaul.micronautjsonapi.identifiable.JsonApiResourceable;
import io.github.baylorpaul.micronautjsonapi.model.JsonApiObject;
import io.github.baylorpaul.micronautjsonapi.model.JsonApiResource;
import io.github.baylorpaul.micronautjsonapi.model.JsonApiTopLevelResource;
import io.github.baylorpaul.micronautjsonapi.util.JsonApiUtil;
import io.github.baylorpaul.webauthn4jmicronaut.repo.UserRepository;
import io.github.baylorpaul.webauthn4jmicronaut.rest.UserRestService;
import io.github.baylorpaul.webauthn4jmicronaut.security.SecurityUtil;
import io.github.baylorpaul.webauthn4jmicronaut.service.UserService;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.*;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import jakarta.inject.Inject;
import jakarta.validation.constraints.NotBlank;

import java.security.Principal;
import java.util.Optional;

@ExecuteOn(TaskExecutors.IO)
@Controller("/users")
public class UserController {

	@Inject
	private UserRepository userRepo;

	@Inject
	private UserService userService;

	@Inject
	private UserRestService userRestService;

	@Secured(SecurityRule.IS_AUTHENTICATED)
	@Get("/me")
	public Optional<JsonApiTopLevelResource> showMe(Principal principal) {
		long id = SecurityUtil.requireUserId(principal);
		return userRepo.findById(id)
				.map(JsonApiResourceable::toTopLevelResource);
	}

	/**
	 * Send an email with a link to a user that is requesting to add a passkey.
	 * Even if the user does not exist, and no email is sent, this will return HTTP status 200 (OK).
	 * @param addPasskeyUriPathWithoutToken the path in the web app URL to add a passkey, such as "/login/addPasskeyViaToken"
	 */
	@Secured(SecurityRule.IS_ANONYMOUS) // no security
	@Post("/methods/sendPasskeyAdditionLinkEmail")
	public HttpResponse<?> sendPasskeyAdditionLinkEmail(
			@NonNull @NotBlank String addPasskeyUriPathWithoutToken,
			@NonNull @NotBlank String email
	) {
		boolean success = userService.sendPasskeyAdditionLinkEmail(addPasskeyUriPathWithoutToken, email);
		// Even if we can't send the email above, we'll still indicate success, in order to provide less information to the client.
		return HttpResponse.ok();
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
