import React from "react";

interface UsernameInputProps {
	name: string,
	setName: (newVal: string) => void,
	/** true if the field is required */
	required?: boolean,
}
export function UsernameInput(props: UsernameInputProps): React.JSX.Element {
	const {name, setName, required} = props;
	return (<>
		Name:{' '}
		<input
			type="text"
			required={required}
			value={name}
			onChange={e => setName(e.target.value)}
			autoComplete="name"
			autoCorrect="off"
			spellCheck="false"
			maxLength={256}
		/>
	</>);
}

interface EmailInputProps {
	email: string,
	/** null if the email cannot be changed, else a function to change the email */
	setEmail?: (newVal: string) => void,
}
export function EmailInput(props: EmailInputProps): React.JSX.Element {
	const {email, setEmail} = props;
	return (<>
		Email address:{' '}
		<input
			type="email"
			required
			value={email}
			onChange={e => !setEmail ? null : setEmail(e.target.value)}
			autoComplete="email"
			autoCorrect="off"
			spellCheck="false"
			maxLength={256}
			disabled={!setEmail}
		/>
	</>);
}
