# WebAuthn4J Micronaut library

A [WebAuthn](https://webauthn.io/)/Passkeys library for [Micronaut](https://micronaut.io/) via [WebAuthn4J](https://github.com/webauthn4j/webauthn4j), with a sample app using [PostgreSQL](https://www.postgresql.org/) persistence.

## Developer Setup
### Create a development database Simulated Environment:
	docker compose up -d

### Run the app locally
    ./gradlew run

## Notes

### SECURITY WARNING!
While the "library" is ready to use, the "app" source code is a sample only.
Notice that AuthenticationProviderUserPassword.java does NOT check the password.
Please implement your own solution if modeling after the app.
