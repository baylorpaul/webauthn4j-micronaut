# Versions

## 1.1.3

_June 19, 2025_

### Library

- Introduced PasskeyConfiguration interface for common property sharing.

### Tests

- Moved test methods for generating registration and authentication responses to PasskeyTestUtil.

## 1.1.2

_June 16, 2025_

### Library

- In `PasskeyUtil`, change the default behavior of `AuthenticatorAttachment` from `PLATFORM` to `null`. This allows `PLATFORM` (e.g. Touch ID) or `CROSS_PLATFORM` (e.g. hardware security keys).
- Use a custom serializer/deserializer for some [WebAuthn4J](https://github.com/webauthn4j/webauthn4j) classes. This is to avoid a [Micronaut Serialization](https://micronaut-projects.github.io/micronaut-serialization/latest/guide/) issue with `null` values where the class uses `@JsonValue`. The wrapping class needs to use such serialization, not the class with the `@JsonValue`.

### Sample Backend App

- No changes, but will now support `PLATFORM` or `CROSS_PLATFORM` for `AuthenticatorAttachment` as mentioned above.

### Sample Web App

- Created a new sample web app
  - Register a new account with a Passkey
  - Login with Passkey
  - Lost passkey: Email a code for lost Passkey (or for adding a passkey to another machine)

### Docs

- Added [README](./web/README.md) for sample web app
