import React from "react";

interface DialogWithConfirmProps {
	/** true if the dialog is open */
	isOpen: boolean,
	/** invoked when the dialog is opened */
	onOpen?: () => void,
	/** Callback fired when the component requests to be closed. */
	close: () => void,
	/** The dialog title content */
	title?: React.ReactNode,
	/** The submit button content, or undefined to only show a "close button" */
	submitBtnContent?: React.ReactNode,
	/** undefined if the submit button is disabled, else the callback fired to submit the form */
	onSubmit?: () => Promise<any>,
	/** The dialog content */
	children: React.ReactNode,
}
export function DialogWithConfirm(props: DialogWithConfirmProps) {
	const {isOpen, onOpen, close, title, submitBtnContent, onSubmit, children} = props;

	const dialogRef = React.useRef<HTMLDialogElement>(null);
	const [working, setWorking] = React.useState(false);

	React.useEffect(
		() => {
			if (isOpen) {
				dialogRef.current?.showModal();
				if (onOpen) {
					onOpen();
				}
			} else {
				dialogRef.current?.close();
			}
		},
		[isOpen]
	);

	return (
		<dialog ref={dialogRef}>
			<div>{title}</div>
			<div style={{overflowY: 'visible'}}>
				{children}
			</div>
			<div>
				<button onClick={close}>
					{submitBtnContent ? 'Cancel' : 'OK'}
				</button>
				{submitBtnContent && (
					<button
						onClick={!onSubmit ? undefined : () => {
							setWorking(true);
							onSubmit()
								.then(close)
								.finally(() => setWorking(false))
						}}
						disabled={working || !onSubmit}
					>
						{working ? '...' : submitBtnContent}
					</button>
				)}
			</div>
		</dialog>
	);
}
