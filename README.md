# WebAuthn4J Micronaut library

A [WebAuthn](https://webauthn.io/)/Passkeys library for [Micronaut](https://micronaut.io/) via [WebAuthn4J](https://github.com/webauthn4j/webauthn4j), with a sample app using [PostgreSQL](https://www.postgresql.org/) persistence.

## Developer Setup
### Create a development database Simulated Environment:
	docker compose up -d

### Run the app locally
    ./gradlew run

## Notes

### MAJOR SECURITY WARNING!
While the "library" is ready to use, the "app" source code is a sample only.
Notice that PasswordUtil.java DOES NOT check a user's password.
Please implement your own solution if modeling after the app.
The password is always "topsecret".

### Email
Email is not implemented in the sample app. The basic contents are logged instead.
See MailTemplateService.java
