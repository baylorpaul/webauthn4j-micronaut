// Utilities for making fetch() requests to APIs using the JSON:API specification

import type {JsonApiErrorResponse} from "@baylorpaul/json-api-bridge";

export const SERVICE_UNAVAILABLE_ERROR: Partial<FetchError> = {
	status: 503,
	firstErrorMessage: 'Service Unavailable',
};

export interface FetchError extends Response {
	/** the first error message found, as determined by API response format */
	firstErrorMessage?: string,
}

/**
 * a type definition matching fetch(). This is useful in cases where custom handling is desired without requiring each
 * caller to make the same changes. E.g. adding headers or handling errors.
 */
export type FetchFn = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

/**
 * Invoke a fetch() request. If a TypeError is thrown, convert it to a FetchError.
 */
export function fetchOrFetchError(
	input: RequestInfo | URL,
	init?: RequestInit,
	options?: {errorResponseConverter?: (errorResponse: any) => string|undefined}
): Promise<Response> {
	if ((init?.method?.toUpperCase() === 'GET' || !init?.method) && !init?.cache) {
		init = {
			...init,
			// Ensure we always fetch the resource from the remote server without using cache.
			// See https://developer.mozilla.org/en-US/docs/Web/API/Request/cache
			cache: 'no-store',
		};
	}
	const result = fetch(input, init);
	return wrapErrorsAsFetchError(result, options?.errorResponseConverter ?? readErrorMessagesAsString);
}

/**
 * Wrap rejected promises as a FetchError. And if the Promise is resolved, but the response is not "ok", reject the
 * Promise with a FetchError.
 */
async function wrapErrorsAsFetchError(
	r: Promise<Response>,
	errorResponseConverter: (errorResponse: any) => string|undefined
): Promise<Response> {
	return r
		.catch(convertTypeErrorToFetchErrorRejection)
		.then(r => rejectAsJsonIfNotOkay(r, errorResponseConverter));
}

/**
 * Check the response, and if it was not "ok", read the error response body as JSON, and return a rejected promise.
 * For a failure response, we're expecting to process the body as JSON.
 */
async function rejectAsJsonIfNotOkay(
	r: Response,
	errorResponseConverter: (errorResponse: any) => string|undefined
): Promise<Response> {
	if (!r.ok) {
		// The body is an error response.
		// The response may require r.text(), but using r.json() works for our use cases, other than the fact that we
		// won't be able to read the error response:
		// https://developer.mozilla.org/en-US/docs/Web/API/Response/text
		return r.json()
			.then((errorResponse: any) => Promise.reject(convertToFetchError(r, errorResponseConverter(errorResponse))));
	}
	return Promise.resolve(r);
}

/**
 * A call to fetch() may throw a TypeError in some cases. If we catch one, convert it to a Promise rejected with a FetchError.
 * @see https://developer.mozilla.org/en-US/docs/Web/API/fetch#exceptions
 */
function convertTypeErrorToFetchErrorRejection(r: TypeError): Promise<never> {
	// E.g. the server is down, or we're using a path that doesn't exist, where a preflight request responded with an
	// HTTP 401, so our actual request is rejected.
	const fetchError: Partial<FetchError> = {
		...SERVICE_UNAVAILABLE_ERROR,
		statusText: r?.name + (r?.message ? `: ${r?.message}` : ''),
	};
	return Promise.reject(fetchError);
}

function readErrorMessagesAsString(errorResponse: JsonApiErrorResponse): string|undefined {
	const {errors} = errorResponse ?? {};
	const errorStrs = errors && errors.length > 0
		? errors.map(err => err?.detail).filter(str => !!str)
		: [];
	return errorStrs.join(', ') ?? undefined;
}

function convertToFetchError(r: Response, firstErrorMessage: string|undefined): Partial<FetchError> {
	return {
		redirected: r.redirected,
		status: r.status,
		statusText: r.statusText,
		type: r.type,
		url: r.url,
		firstErrorMessage
	};
}

/**
 * @return a human friendly error message string
 */
export function buildStringFromFetchError(fetchError: Partial<FetchError>): string|undefined {
	const {status, statusText, firstErrorMessage} = fetchError ?? {};
	return firstErrorMessage ?? statusText ?? (status ? `HTTP ${status}` : undefined);
}
