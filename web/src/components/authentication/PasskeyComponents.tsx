import React from "react";
import {ErrorAlert, FormNoSubmit} from "../common/CommonUI.tsx";
import {EmailInput, UsernameInput} from "../common/CommonInputs.tsx";
import {
	addPasskeyViaEmailedToken,
	authenticateViaPasskeyForAccessTokenResponse,
	isPasskeySupported,
	registerPasskey, verifyAuthenticationViaPasskeyAsAuthenticatedUserForConfirmationTokenResponse
} from "../../api/authentication/webAuthn.ts";
import {DialogWithConfirm} from "../common/Dialogs.tsx";
import {buildStringFromFetchError, type FetchError, type FetchFn, fetchOrFetchError} from "../../utility/fetchUtil.ts";
import {joinErrorMessages} from "../../utility/commonUtil.ts";
import {useSearchParams} from "react-router";

interface LoginWithPasskeyFormProps<R> {
	/** the authentication server URL, such as 'http://example.com' */
	authenticationServerUrl: string,
	createUserDialogOpen: boolean,
	resetPasskeyDialogOpen: boolean,
	addPasskeyFromEmailedTokenDialogOpen: boolean,
	closeDialog: () => void,
	/**
	 * Notify the user of a successful message, such as via a "snackbar" or alert. This is invoked when a passkey is
	 * registered, or if an email is sent to reset the passkey.
	 */
	notifySuccessMessage: (msg: string) => void,
	/** The function to call when the passkey login is successful */
	onLoginSuccess: (resp: R) => void,
}
export function LoginWithPasskeyForm<R>(props: LoginWithPasskeyFormProps<R>): React.JSX.Element {
	const {authenticationServerUrl, createUserDialogOpen, resetPasskeyDialogOpen, addPasskeyFromEmailedTokenDialogOpen, closeDialog, notifySuccessMessage, onLoginSuccess} = props;

	const [errorMsg, setErrorMsg] = React.useState<string>();
	const passkeySupported = React.useMemo(() => isPasskeySupported(), []);

	const verifyPasskeyAuthentication = (): Promise<any> => authenticateViaPasskeyForAccessTokenResponse(authenticationServerUrl)
		.then(verificationResp => verificationResp.json())
		.then(onLoginSuccess)
		.catch(r => setErrorMsg(joinErrorMessages('Unable to login', buildStringFromFetchError(r))));

	return (<>
		{!passkeySupported && (
			<ErrorAlert errorMsg="Your browser does not support Passkeys/WebAuthn. Choose another login method."/>
		)}
		<ErrorAlert
			errorMsg={errorMsg}
			setErrorMsg={setErrorMsg}
		/>

		{passkeySupported && (<>
			<PasskeyLogin
				verifyAuthentication={verifyPasskeyAuthentication}
			/>

			<CreateUserWithPasskeyFormDialog
				authenticationServerUrl={authenticationServerUrl}
				open={createUserDialogOpen}
				onClose={closeDialog}
				notifySuccessMessage={notifySuccessMessage}
			/>

			<ResetPasskeyForm
				authenticationServerUrl={authenticationServerUrl}
				open={resetPasskeyDialogOpen}
				onClose={closeDialog}
				notifySuccessMessage={notifySuccessMessage}
			/>

			<AddPasskeyFromEmailedTokenForm
				authenticationServerUrl={authenticationServerUrl}
				open={addPasskeyFromEmailedTokenDialogOpen}
				onClose={closeDialog}
				notifySuccessMessage={notifySuccessMessage}
			/>
		</>)}
	</>);
}

interface PasskeyButtonProps {
	/** the button content */
	btnContent: React.ReactNode,
	/** The function to call when the passkey login is submitted, or falsy if disabled */
	verifyAuthentication?: () => Promise<any>,
}
export function PasskeyButton(props: PasskeyButtonProps): React.JSX.Element {
	const {btnContent, verifyAuthentication} = props;

	const [working, setWorking] = React.useState(false);

	return (
		<button
			onClick={() => {
				if (verifyAuthentication) {
					setWorking(true);
					verifyAuthentication()
						.finally(() => setWorking(false));
				}
			}}
			disabled={working || !verifyAuthentication}
		>
			{working ? '...' : btnContent}
		</button>
	);
}

interface PasskeyLoginProps {
	/** The function to call when the passkey login is submitted */
	verifyAuthentication: () => Promise<any>,
}
function PasskeyLogin(props: PasskeyLoginProps): React.JSX.Element {
	const {verifyAuthentication} = props;

	return (<>
		<div style={{paddingBottom: '20px'}}>
			<PasskeyButton
				btnContent="Login with Passkey"
				verifyAuthentication={verifyAuthentication}
			/>
		</div>
		<div>
			<a href="/login/resetPasskey">
				Lost passkey?
			</a>
		</div>
	</>);
}

interface PasskeyReVerificationProps {
	/**
	 * the fetch function, which automatically includes appropriate headers and handles errors. E.g. a simple
	 * implementation may invoke fetchOrFetchError() while including an "Authorization" HTTP header in "init.headers".
	 */
	fetchFn: FetchFn,
	/** the authentication server URL, such as 'http://example.com' */
	authenticationServerUrl: string,
	/** The function to call when the passkey login is submitted */
	onSubmit: (promise: Promise<string>) => Promise<any>,
}

/**
 * Re-verify authentication via passkey for a user who has already logged in. This is used for protected actions, such
 * as changing a password, adding an integration token, or adding another passkey to the user's account.
 */
export function PasskeyReVerification(props: PasskeyReVerificationProps): React.JSX.Element {
	const {fetchFn, authenticationServerUrl, onSubmit} = props;

	const verifyAuthentication = (): Promise<any> => onSubmit(
		verifyAuthenticationViaPasskeyAsAuthenticatedUserForConfirmationTokenResponse(fetchFn, authenticationServerUrl)
			.then(verificationResp => verificationResp.text())
	);

	return (
		<PasskeyButton
			btnContent="Verify with Passkey"
			verifyAuthentication={verifyAuthentication}
		/>
	);
}

interface CreateUserWithPasskeyFormDialogProps {
	/** the authentication server URL, such as 'http://example.com' */
	authenticationServerUrl: string,
	open: boolean,
	onClose: () => void,
	/** Notify the user of a successful message, such as via a "snackbar" or alert */
	notifySuccessMessage: (msg: string) => void,
}
function CreateUserWithPasskeyFormDialog(props: CreateUserWithPasskeyFormDialogProps): React.JSX.Element {
	const {authenticationServerUrl, open, onClose, notifySuccessMessage} = props;

	const [email, setEmail] = React.useState('');
	const [name, setName] = React.useState('');
	const [errorMsg, setErrorMsg] = React.useState<string>();

	async function onSubmit(): Promise<any> {
		return registerPasskey(authenticationServerUrl, email, name)
			.then(() => notifySuccessMessage('Successfully registered! You may now Login...'))
			.catch(r => {
				setErrorMsg(joinErrorMessages('Unable to sign up via passkey', buildStringFromFetchError(r)));
				throw r;
			});
	}

	return (
		<DialogWithConfirm
			isOpen={open}
			onOpen={() => setErrorMsg(undefined)}
			close={onClose}
			title="Create an Account and Passkey"
			submitBtnContent="Register via Passkey"
			onSubmit={onSubmit}
		>
			<FormNoSubmit>

				<ErrorAlert
					errorMsg={errorMsg}
					setErrorMsg={setErrorMsg}
				/>

				<div>
					<UsernameInput
						name={name}
						setName={setName}
					/>
				</div>
				<div>
					<EmailInput
						email={email}
						setEmail={setEmail}
					/>
				</div>
			</FormNoSubmit>
		</DialogWithConfirm>
	);
}

interface ResetPasskeyFormProps {
	/** the authentication server URL, such as 'http://example.com' */
	authenticationServerUrl: string,
	defaultEmail?: string,
	open: boolean,
	onClose: () => void,
	/** Notify the user of a successful message, such as via a "snackbar" or alert */
	notifySuccessMessage: (msg: string) => void,
}
function ResetPasskeyForm(props: ResetPasskeyFormProps): React.JSX.Element {
	const {authenticationServerUrl, defaultEmail, open, onClose, notifySuccessMessage} = props;
	const sendPasskeyAdditionLinkEmailLocal = (email: string) => sendPasskeyAdditionLinkEmail(
		authenticationServerUrl,
		email,
		"/login/addPasskeyViaToken"
	);

	const [email, setEmail] = React.useState('');
	const [errorMsg, setErrorMsg] = React.useState<string>();

	async function onSubmit(): Promise<any> {
		return sendPasskeyAdditionLinkEmailLocal(email)
			.then(_result => notifySuccessMessage('Sent passkey addition email (if user email exists).\n\nIf this is a development server, check the server logs.'))
			.catch((e: Partial<FetchError>) => {
				const errorMsg = buildStringFromFetchError(e);
				setErrorMsg(joinErrorMessages('Unable to request a passkey addition email', errorMsg));
				throw errorMsg;
			});
	}

	return (
		<DialogWithConfirm
			isOpen={open}
			onOpen={() => {
				setErrorMsg(undefined);
				setEmail(defaultEmail ?? '');
			}}
			close={onClose}
			title="Reset Your Passkey"
			submitBtnContent="Continue"
			onSubmit={onSubmit}
		>
			<div>
				Enter the email address for your account, and we'll email you a link to reset your passkey.
			</div>

			<FormNoSubmit>
				<ErrorAlert
					errorMsg={errorMsg}
					setErrorMsg={setErrorMsg}
				/>

				<div>
					<EmailInput
						email={email}
						setEmail={setEmail}
					/>
				</div>
			</FormNoSubmit>
		</DialogWithConfirm>
	);
}

/**
 * Send an email with a link to a user that is requesting to add a passkey. If the promise is rejected, it is rejected
 * with a FetchError.
 * @param authenticationServerUrl
 * @param email
 * @param addPasskeyUriPathWithoutToken the path in the web app URL to add a passkey, such as "/login/addPasskeyViaToken"
 */
export function sendPasskeyAdditionLinkEmail(
	authenticationServerUrl: string,
	email: string,
	addPasskeyUriPathWithoutToken: string
): Promise<any> {
	return fetchOrFetchError(`${authenticationServerUrl}/users/methods/sendPasskeyAdditionLinkEmail`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify({
			addPasskeyUriPathWithoutToken: addPasskeyUriPathWithoutToken,
			email: email
		})
	});
}

interface AddPasskeyFromEmailedTokenFormProps {
	/** the authentication server URL, such as 'http://example.com' */
	authenticationServerUrl: string,
	open: boolean,
	onClose: () => void,
	/** Notify the user of a successful message, such as via a "snackbar" or alert */
	notifySuccessMessage: (msg: string) => void,
}
function AddPasskeyFromEmailedTokenForm(props: AddPasskeyFromEmailedTokenFormProps): React.JSX.Element {
	const {authenticationServerUrl, open, onClose, notifySuccessMessage} = props;

	const [errorMsg, setErrorMsg] = React.useState<string>();

	const [searchParams] = useSearchParams();
	// Get the email, just for display purposes
	const email = searchParams.get("email");
	const token = searchParams.get("token");

	async function onSubmit(): Promise<any> {
		if (token) {
			return addPasskeyViaEmailedToken(authenticationServerUrl, token)
				.then(() => notifySuccessMessage('Successfully added passkey! You may now Login...'))
				.catch(r => {
					setErrorMsg(joinErrorMessages('Unable to add passkey', buildStringFromFetchError(r)));
					throw r;
				});
		} else {
			// No need to set the error message state. We should already be showing this error.
			return Promise.reject('no token provided');
		}
	}

	const dataErrors = React.useMemo(
		() => !open ? [] : [
			email ? '' : 'Email address unknown',
			token ? '' : 'Invalid request - Token required',
		].filter(str => !!str),
		[open, email, token]
	);

	return (
		<DialogWithConfirm
			isOpen={open}
			onOpen={() => setErrorMsg(undefined)}
			close={onClose}
			title="Add a Passkey"
			submitBtnContent="Create Passkey"
			onSubmit={dataErrors.length > 0 ? undefined : onSubmit}
		>
			<FormNoSubmit>
				{dataErrors?.map((dataError, idx) => (
					<ErrorAlert
						key={idx}
						errorMsg={dataError}
					/>
				))}
				<ErrorAlert
					errorMsg={errorMsg}
					setErrorMsg={setErrorMsg}
				/>

				{email && (
					<div>
						<EmailInput
							email={email}
						/>
					</div>
				)}
			</FormNoSubmit>
		</DialogWithConfirm>
	);
}
