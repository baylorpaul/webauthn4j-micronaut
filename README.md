# WebAuthn4J Micronaut library

A [WebAuthn](https://webauthn.io/)/Passkeys library for [Micronaut](https://micronaut.io/) via [WebAuthn4J](https://github.com/webauthn4j/webauthn4j), with a sample app using [PostgreSQL](https://www.postgresql.org/) persistence.

![Main Screen](./docs/media/01-main-screen.png)

![Authenticate](./docs/media/04-authenticate.png)

## Library Setup

#### Add Dependency to your `build.gradle`
```groovy
dependencies {
    implementation("io.github.baylorpaul:webauthn4j-micronaut:1.1.1")
}
```

Then add API methods to your app, as demonstrated in the provided sample app's PasskeyController.java and UserController.java

## Serialization Exceptions
If you encounter a serialization exception for any WebAuthn4J classes such as the following, please submit an issue or pull request.
While it is possible to resolve it in your own project, it would be best for the community to solve it in this library by adding the appropriate `@SerdeImport`s to `WebAuthn4jSerdeConfig.java`. Unit tests are also welcome!

	IntrospectionException: No serializable introspection present for type XXX xxx. Consider adding Serdeable. Serializable annotate to type XXX xxx. Alternatively if you are not in control of the project's source code, you can use @SerdeImport(XXX.class) to enable serialization of this type.


## Developer Setup for the Sample Application
### Create a development database Simulated Environment:
	docker compose up -d

### Run the app locally
    ./gradlew run

### Run the app tests
	./gradlew :app:test

### Run the app tests natively
	./gradlew :app:nativeTest

## Start the sample web app

See the [Sample Web App README](web/README.md).

## Notes

### MAJOR SECURITY WARNING!
While the "library" is ready to use, the "app" source code is a sample only.
Notice that PasswordUtil.java DOES NOT check a user's password.
Please implement your own solution if modeling after the app.
The password is always:

`topsecret`

A suggested solution is to remove password support entirely, and rely only on WebAuthn/Passkeys and/or Federated Logins.
Passwords are partially implemented here only to demonstrate using alternate authentication methods to add Passkeys.

### Email
Email is not implemented in the sample app. The basic contents are logged instead.
See MailTemplateService.java

### JSON:API Specification

The app uses the [JSON:API](https://jsonapi.org/) specification via the [Micronaut JSON:API library](https://github.com/baylorpaul/micronaut-json-api).
That is why the `application.properties` has set:

	micronaut.serde.serialization.inclusion=non_absent

This will continue omitting null and Optional.empty(), but for the JSON:API spec, include empty collections.
I.e. it is desirable to have `"attributes":{}` instead of excluding `attributes`.
