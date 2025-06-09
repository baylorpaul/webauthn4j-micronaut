
export function joinErrorMessages(leadErrorMsg: string, supplementalErrorMsg?: any): string {
	return [
		leadErrorMsg,
		typeof supplementalErrorMsg === 'string' ? supplementalErrorMsg : undefined
	].filter(v => !!v).join(': ');
}
