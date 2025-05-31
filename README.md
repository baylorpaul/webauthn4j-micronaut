# WebAuthn4J Micronaut library

A [WebAuthn](https://webauthn.io/)/Passkeys library for [Micronaut](https://micronaut.io/) via [WebAuthn4J](https://github.com/webauthn4j/webauthn4j), with a sample app using [PostgreSQL](https://www.postgresql.org/) persistence.

## Developer Setup
### Create a development database Simulated Environment:
	docker compose up -d

### Run the app locally
    ./gradlew run

### Run the app tests natively

	./gradlew :app:nativeTest

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
