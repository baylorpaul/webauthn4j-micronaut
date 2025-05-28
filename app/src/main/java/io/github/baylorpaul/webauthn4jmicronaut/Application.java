package io.github.baylorpaul.webauthn4jmicronaut;

import io.micronaut.context.env.Environment;
import io.micronaut.runtime.Micronaut;

public class Application {

	public static void main(String[] args) {
		Micronaut.build(args)
				.mainClass(Application.class)
				// Default to the "dev" and "dev-top-secret" environments if none other are specified
				.defaultEnvironments(Environment.DEVELOPMENT, "dev-top-secret")
				.start();
	}
}
