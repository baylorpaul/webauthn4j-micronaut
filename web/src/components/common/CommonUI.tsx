import React from "react";

interface FormNoSubmitProps {
	children: React.ReactNode,
}

/**
 * A non-submitting form used for form-autocompletion, such as passwords, addresses, etc.
 * Standard form submissions are rarely required in a single page app (SPA).
 */
export function FormNoSubmit(props: FormNoSubmitProps): React.JSX.Element {
	const {children} = props;
	return (
		<form onSubmit={event => { event.preventDefault(); }}>
			{children}
		</form>
	);
}

export function ErrorAlert(props: {errorMsg?: string, setErrorMsg?: (newErrorMsg: string|undefined) => void}): React.JSX.Element {
	const {errorMsg, setErrorMsg} = props;
	return (<>
		{errorMsg && (
			<div style={{backgroundColor: 'black', color: '#fbb', padding: '20px', fontWeight: 'bold'}}>
				{errorMsg}

				{setErrorMsg && (<>
					<span style={{paddingLeft: '10px'}}/>
					<button type="button" onClick={() => setErrorMsg(undefined)}>X</button>
				</>)}
			</div>
		)}
	</>);
}
