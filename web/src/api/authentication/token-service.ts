/**
 * For access token refresh, use a small margin of error in seconds for the "expires_in" duration so that we are likely
 * to catch the expiration before it happens. E.g. if the HTTP login response took long to return, and now the
 * "expires_in" should actually be a smaller value. But we won't use this value if the "expires_in" duration is too
 * short. We don't want to be perpetually refreshing too early in that case.
 */
const MIN_TOKEN_TTL_SECONDS = 2;

/**
 * A BearerAccessRefreshToken that encapsulates an Access Token response as described in
 * <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.4">RFC 6749</a>.
 */
export interface LoginResponse {
	access_token: string,
	refresh_token?: string,
	/** The token type, such as "Bearer" */
	token_type?: string,
	/** The number of seconds the access token is valid since it was issued */
	expires_in: number,
	username?: string,
}

export interface LoginResponseAndExpiration extends LoginResponse {
	/**
	 * the expiration time in epoch milliseconds of the access token, computed using the client's clock and the
	 * "expires_in" duration when the access token was issued.
	 * If the "expires_in" duration is too short, this value will not be set.
	 */
	localExpireTime?: number,
}

export function applyLocalExpireTime(r: LoginResponse): LoginResponseAndExpiration {
	// If the "expires in" time is really short, don't bother storing the expiration time. Since we may refresh the
	// token ahead of time, we don't want to refresh the token for every request if the expiration duration is too short
	return r.expires_in && r.expires_in > MIN_TOKEN_TTL_SECONDS
		? {...r, localExpireTime: Date.now() + r.expires_in * 1000}
		: r;
}
