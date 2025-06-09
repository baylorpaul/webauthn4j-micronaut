
/**
 * A request that verifies user identity
 */
export interface UserVerificationDto {
	/** the platform on which we are authenticating. Expecting one of "android", "ios", or "web" */
	platform: string,
	/** A short-lived JWT Confirmation Token, which was issued when passkey access was verified */
	jwtPasskeyAccessVerifiedToken?: string,
	/** A raw password, if authenticating via password */
	password?: string,
}
