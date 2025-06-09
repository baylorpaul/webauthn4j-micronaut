import React from 'react';
import {APP_TITLE, SERVER_URL} from "../appConfig.tsx";
import {useMatch, useNavigate, useSearchParams} from "react-router";
import {LoginWithPasskeyForm} from "../components/authentication/PasskeyComponents.tsx";
import {
	applyLocalExpireTime,
	type LoginResponse,
	type LoginResponseAndExpiration
} from "../api/authentication/token-service.ts";
import {isPasskeySupported} from "../api/authentication/webAuthn.ts";

export function LoginForm(): React.JSX.Element {
	const navigate = useNavigate();
	const matchesSignUpWithPasskey = !!useMatch('/login/signupWithPasskey');
	const matchesResetPasskey = !!useMatch('/login/resetPasskey');
	const matchesAddPasskeyFromEmailedToken = !!useMatch('/login/addPasskeyViaToken');

	const [loginResponse, setLoginResponse] = React.useState<LoginResponseAndExpiration|undefined>(undefined);

	const passkeySupported = React.useMemo(() => isPasskeySupported(), []);

	const [searchParams] = useSearchParams();
	const redirectUri = searchParams.get("redirectUri");

	const notifySuccessMessage = React.useCallback(
		(msg: string) => alert(msg),
		[]
	);

	React.useEffect(() => {
		if (loginResponse) {
			// The user is already logged in. Redirect them.
			if (redirectUri) {
				navigate(redirectUri);
			} else {
				alert('You successfully logged in!');
			}
		}
	}, [loginResponse, redirectUri]);

	return (
		<div>
			<h4>{APP_TITLE}</h4>

			<div style={{paddingBottom: '20px'}}>
				<div>Don't have an account?</div>
				{passkeySupported && (
					<div>
						<a href="/login/signupWithPasskey">
							Get started with passkey
						</a>
					</div>
				)}
			</div>

			<LoginWithPasskeyForm
				authenticationServerUrl={SERVER_URL}
				createUserDialogOpen={matchesSignUpWithPasskey}
				resetPasskeyDialogOpen={matchesResetPasskey}
				addPasskeyFromEmailedTokenDialogOpen={matchesAddPasskeyFromEmailedToken}
				closeDialog={() => navigate('/login')}
				notifySuccessMessage={notifySuccessMessage}
				onLoginSuccess={(lr: LoginResponse) => {
					const lre = applyLocalExpireTime(lr);
					setLoginResponse(lre);
				}}
			/>
		</div>
	);
}
