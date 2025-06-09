import {
	type AuthenticationResponseJSON,
	browserSupportsWebAuthn,
	type PublicKeyCredentialCreationOptionsJSON,
	type PublicKeyCredentialRequestOptionsJSON,
	type RegistrationResponseJSON
} from "@simplewebauthn/browser";
import { startAuthentication, startRegistration } from '@simplewebauthn/browser';
import queryString from 'query-string';
import {type FetchFn, fetchOrFetchError} from "../../utility/fetchUtil.ts";
import {type UserVerificationDto} from "../dto/api/UserVerificationDto.ts";

interface PublicKeyCredentialCreationOptionsSession {
	challengeSessionId: string,
	publicKeyCredentialCreationOptionsJSON: PublicKeyCredentialCreationOptionsJSON,
}

interface PublicKeyCredentialRequestOptionsSession {
	challengeSessionId: string,
	publicKeyCredentialRequestOptionsJSON: PublicKeyCredentialRequestOptionsJSON,
}

export interface RegistrationResponseSession {
	challengeSessionId: string,
	registrationResponseJSON: RegistrationResponseJSON,
}

export interface AuthenticationResponseSession {
	challengeSessionId: string,
	authenticationResponseJSON: AuthenticationResponseJSON,
}

/**
 * Determine if the browser has the ability to make WebAuthn/Passkey API calls. This may be used to show error content
 * instead of requesting the user to login via WebAuthn/Passkeys.
 */
export function isPasskeySupported(): boolean {
	return browserSupportsWebAuthn();
}

/**
 * Register a passkey for a new account via WebAuthn
 * @see <a href="https://simplewebauthn.dev/docs/packages/browser#startregistration">startRegistration() via @simplewebauthn/browser</a>
 */
export async function registerPasskey(authenticationServerUrl: string, uniqueNameOrEmail: string, displayName: string): Promise<Response> {
	const optionsSession = await generateRegistrationOptionsJson(authenticationServerUrl, uniqueNameOrEmail, displayName);
	return startAndVerifyRegistration(authenticationServerUrl, optionsSession);
}

/**
 * Add a passkey to an existing account via a token
 */
export async function addPasskeyViaEmailedToken(authenticationServerUrl: string, token: string): Promise<Response> {
	const optionsSession = await generatePasskeyRegistrationOptionsJsonForExistingAccount(authenticationServerUrl, token);
	return startAndVerifyRegistration(authenticationServerUrl, optionsSession);
}

/**
 * To add a passkey to an existing account, register a passkey as an authenticated user
 * @param fetchFn the fetch function, which automatically includes appropriate headers and handles errors. E.g. a simple
 *            implementation may invoke fetchOrFetchError() while including an "Authorization" HTTP header in
 *            "init.headers".
 * @param authenticationServerUrl
 * @param userVerificationDto information that re-verifies user identity
 * @see <a href="https://simplewebauthn.dev/docs/packages/browser#startregistration">startRegistration() via @simplewebauthn/browser</a>
 */
export async function registerPasskeyAsAuthenticatedUser(
	fetchFn: FetchFn,
	authenticationServerUrl: string,
	userVerificationDto: UserVerificationDto
): Promise<Response> {
	const optionsSession = await generateRegistrationOptionsJsonAsAuthenticatedUser(fetchFn, authenticationServerUrl, userVerificationDto);
	return startAndVerifyRegistration(authenticationServerUrl, optionsSession);
}

async function startAndVerifyRegistration(authenticationServerUrl: string, optionsSession: PublicKeyCredentialCreationOptionsSession): Promise<Response> {
	const {challengeSessionId, publicKeyCredentialCreationOptionsJSON: optionsJSON} = optionsSession;

	// Pass the options to the authenticator and wait for a response
	let attResp: RegistrationResponseJSON = await startRegistration({ optionsJSON })
		.catch(r => {
			// See SimpleWebAuthn error types - https://github.com/MasterKale/SimpleWebAuthn/issues/357
			const previouslyRegistered = r?.code === 'ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED';
			if (previouslyRegistered) {
				const newError: Partial<Response> = {
					...r,
					status: 409,
					// SimpleWebAuthn says "The authenticator was previously registered"
					statusText: 'You already have a registered passkey for this authenticator.',
				};
				throw newError;
			} else {
				throw r;
			}
		});

	const regRespSession: RegistrationResponseSession = {
		challengeSessionId: challengeSessionId,
		registrationResponseJSON: attResp,
	};
	return verifyRegistrationJson(authenticationServerUrl, regRespSession);
}

/**
 * Login via a passkey for an existing account
 * @see <a href="https://simplewebauthn.dev/docs/packages/browser#startauthentication">startAuthentication() via @simplewebauthn/browser</a>
 * @return a response with a JWT access token, refresh token, etc.
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.4">Access Token Response</a>
 */
export async function authenticateViaPasskeyForAccessTokenResponse(
	authenticationServerUrl: string
): Promise<Response> {
	// Start the authentication process
	// GET authentication options. E.g. @simplewebauthn/server -> generateAuthenticationOptions()
	const optionsSession = await fetchOrFetchError(
		`${authenticationServerUrl}/passkeys/methods/generateAuthenticationOptions`,
		{method: 'GET', cache: 'no-store'}
	)
		.then(resp => resp.json())
		.then(translateBytesForRequestOptions);

	const authRespSession = await authenticatorLogin(optionsSession);

	return verifyAuthentication(
		fetchOrFetchError,
		`${authenticationServerUrl}/passkeys/methods/verifyAuthenticationForAccessTokenResponse`,
		authRespSession
	);
}

/**
 * Login via a passkey as an already authenticated user, with the intent to confirm access to the account. This may be
 * used so that protected actions may be taken. E.g. adding an integration token, changing a user's password, or adding
 * a passkey to the user's account. The authentication options shall include "allowCredentials" values, if available.
 * @param fetchFn the fetch function, which automatically includes appropriate headers and handles errors. E.g. a simple
 *            implementation may invoke fetchOrFetchError() while including an "Authorization" HTTP header in
 *            "init.headers".
 * @param authenticationServerUrl
 * @return a response with a "passkey access verified" confirmation token
 */
export async function verifyAuthenticationViaPasskeyAsAuthenticatedUserForConfirmationTokenResponse(
	fetchFn: FetchFn,
	authenticationServerUrl: string
): Promise<Response> {

	// Start the re-authentication process as an already authenticated user
	const optionsSession = await fetchFn(
		`${authenticationServerUrl}/passkeys/methods/generateAuthenticationOptionsAsAuthenticatedUser`,
		{method: 'GET', cache: 'no-store'}
	)
		.then(resp => resp.json())
		.then(translateBytesForRequestOptions);

	const authRespSession = await authenticatorLogin(optionsSession);

	// Re-verify authentication
	return verifyAuthentication(
		fetchFn,
		`${authenticationServerUrl}/passkeys/methods/verifyAuthenticationAsAuthenticatedUserForConfirmationTokenResponse`,
		authRespSession
	);
}

/**
 * A less-preferred passkey verification function that does NOT require authentication. The intent is to confirm access
 * to an account. While not being authenticated has no security concerns, it does not ensure that passkey selected
 * belongs to the expected user. As such, the requestor will get an error message later in the process if they pick a
 * passkey for the wrong user. That will be when the requestor attempts to use the passkey access confirmation token to
 * e.g. login via federated login for the first time on a pre-existing account.
 * This function will provide a confirmation token so that protected actions may be taken. E.g. connecting a federated
 * login to a pre-existing account, adding an integration token, changing a user's password, or adding a passkey to the
 * user's account. The authentication options shall NOT include "allowCredentials" values, because no user credentials
 * are specified. That means any credentials may be selected, but the confirmation token will not succeed if paired with
 * the wrong credentials.
 * @param authenticationServerUrl
 * @return a response with a "passkey access verified" confirmation token
 */
export async function verifyAuthenticationViaPasskeyForConfirmationTokenResponse(
	authenticationServerUrl: string
): Promise<Response> {

	// Start the authentication process
	const optionsSession = await fetchOrFetchError(
		`${authenticationServerUrl}/passkeys/methods/generateAuthenticationOptions`,
		{method: 'GET', cache: 'no-store'}
	)
		.then(resp => resp.json())
		.then(translateBytesForRequestOptions);

	const authRespSession = await authenticatorLogin(optionsSession);

	return verifyAuthentication(
		fetchOrFetchError,
		`${authenticationServerUrl}/passkeys/methods/verifyAuthenticationForConfirmationTokenResponse`,
		authRespSession
	);
}

/**
 * @see <a href="https://simplewebauthn.dev/docs/packages/browser#startauthentication">startAuthentication() via @simplewebauthn/browser</a>
 * @return the authentication response
 */
async function authenticatorLogin(
	optionsSession: PublicKeyCredentialRequestOptionsSession
): Promise<AuthenticationResponseSession> {
	const {challengeSessionId, publicKeyCredentialRequestOptionsJSON: optionsJSON} = optionsSession;

	// Pass the options to the authenticator and wait for a response
	let authResp: AuthenticationResponseJSON = await startAuthentication({ optionsJSON, useBrowserAutofill: false });

	return {
		challengeSessionId: challengeSessionId,
		authenticationResponseJSON: authResp,
	};
}

/**
 * GET registration options. E.g. @simplewebauthn/server -> generateRegistrationOptions()
 */
async function generateRegistrationOptionsJson(
	authenticationServerUrl: string,
	uniqueNameOrEmail: string,
	displayName: string
): Promise<PublicKeyCredentialCreationOptionsSession> {
	return fetchOrFetchError(
		`${authenticationServerUrl}/passkeys/methods/generateRegistrationOptions?${queryString.stringify({uniqueNameOrEmail, displayName})}`,
		{method: 'GET', cache: 'no-store'}
	)
		.then(resp => resp.json())
		.then(translateBytesForCreationOptions);
}

/**
 * GET passkey creation options for adding a passkey to an existing account
 */
async function generatePasskeyRegistrationOptionsJsonForExistingAccount(
	authenticationServerUrl: string,
	token: string
): Promise<PublicKeyCredentialCreationOptionsSession> {
	return fetchOrFetchError(`${authenticationServerUrl}/passkeys/methods/generateRegistrationOptionsForExistingAccount`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify({token: token}),
	})
		.then(resp => resp.json())
		.then(translateBytesForCreationOptions);
}

/**
 * POST request to get passkey creation options for adding a passkey to an existing account as an authenticated user
 * @param fetchFn the fetch function, which automatically includes appropriate headers and handles errors. E.g. a simple
 *            implementation may invoke fetchOrFetchError() while including an "Authorization" HTTP header in
 *            "init.headers".
 * @param authenticationServerUrl
 * @param userVerificationDto information that re-verifies user identity
 */
async function generateRegistrationOptionsJsonAsAuthenticatedUser(
	fetchFn: FetchFn,
	authenticationServerUrl: string,
	userVerificationDto: UserVerificationDto
): Promise<PublicKeyCredentialCreationOptionsSession> {
	return fetchFn(`${authenticationServerUrl}/passkeys/methods/generateRegistrationOptionsAsAuthenticatedUser`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify(userVerificationDto),
	})
		.then(resp => resp.json())
		.then(translateBytesForCreationOptions);
}

function translateBytesForCreationOptions(resp: any): PublicKeyCredentialCreationOptionsSession {
	const {challengeSessionId, publicKeyCredentialCreationOptions} = resp;
	return {
		challengeSessionId: challengeSessionId,
		publicKeyCredentialCreationOptionsJSON: publicKeyCredentialCreationOptions,
	};
}

/**
 * POST the registration response, whether for a new user or an existing user.
 * E.g. @simplewebauthn/server -> verifyRegistrationResponse()
 */
async function verifyRegistrationJson(
	authenticationServerUrl: string,
	regRespSession: RegistrationResponseSession
): Promise<Response> {
	const {challengeSessionId, registrationResponseJSON} = regRespSession;
	// POST the response to the endpoint that calls
	// @simplewebauthn/server -> verifyRegistrationResponse()
	return fetchOrFetchError(`${authenticationServerUrl}/passkeys/methods/verifyRegistration`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'X-Challenge-Session-ID': challengeSessionId,
		},
		body: JSON.stringify(registrationResponseJSON),
	});
}

function translateBytesForRequestOptions(resp: any): PublicKeyCredentialRequestOptionsSession {
	const {challengeSessionId, publicKeyCredentialRequestOptions} = resp;
	return {
		challengeSessionId: challengeSessionId,
		publicKeyCredentialRequestOptionsJSON: publicKeyCredentialRequestOptions,
	};
}

/**
 * POST the WebAuthn passkey authentication response
 * E.g. @simplewebauthn/server -> verifyAuthenticationResponse()
 * @param fetchFn the fetch function, which automatically includes appropriate headers and handles errors. E.g. a simple
 *            implementation may invoke fetchOrFetchError(), sometimes including an "Authorization" HTTP header in
 *            "init.headers".
 * @param input the input, such as a URL of `${authenticationServerUrl}/passkeys/methods/verifyAuthenticationForAccessTokenResponse`
 * @param authRespSession the authentication response session information to submit in the body of the message
 * @see <a href="https://simplewebauthn.dev/docs/packages/browser#startauthentication">startAuthentication() via @simplewebauthn/browser</a>
 */
async function verifyAuthentication(
	fetchFn: FetchFn,
	input: RequestInfo | URL,
	authRespSession: AuthenticationResponseSession
): Promise<Response> {
	const {challengeSessionId, authenticationResponseJSON} = authRespSession;
	return fetchFn(input, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'X-Challenge-Session-ID': challengeSessionId,
		},
		body: JSON.stringify(authenticationResponseJSON),
	});
}
