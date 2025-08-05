import { logError, ProviderError } from "@ccflare/core";
import { Logger } from "@ccflare/logger";
import type { Account, RequestMeta } from "@ccflare/types";
import { forwardToClient } from "../response-handler";
import { ERROR_MESSAGES, type ProxyContext } from "./proxy-types";
import { makeProxyRequest } from "./request-handler";
import { handleProxyError, processProxyResponse } from "./response-processor";
import { getValidAccessToken } from "./token-manager";

const log = new Logger("ProxyOperations");

/**
 * Handles proxy request without authentication
 * @param req - The incoming request
 * @param url - The parsed URL
 * @param requestMeta - Request metadata
 * @param requestBodyBuffer - Buffered request body
 * @param createBodyStream - Function to create body stream
 * @param ctx - The proxy context
 * @returns Promise resolving to the response
 * @throws {ProviderError} If the unauthenticated request fails
 */
export async function proxyUnauthenticated(
	req: Request,
	url: URL,
	requestMeta: RequestMeta,
	requestBodyBuffer: ArrayBuffer | null,
	createBodyStream: () => ReadableStream<Uint8Array> | undefined,
	ctx: ProxyContext,
): Promise<Response> {
	log.warn(ERROR_MESSAGES.NO_ACCOUNTS);

	const targetUrl = ctx.provider.buildUrl(url.pathname, url.search);
	const headers = ctx.provider.prepareHeaders(
		req.headers,
		undefined,
		undefined,
	);

	try {
		if (process.env.CF_DEBUG_TRAFFIC === "true") {
			log.info("🔍 REQUEST DETAILS (no account):");
			log.info(`URL: ${targetUrl}`);
			log.info(`Method: ${req.method}`);
			log.info("Headers:", Object.fromEntries(headers.entries()));
		}

		const response = await makeProxyRequest(
			targetUrl,
			req.method,
			headers,
			createBodyStream,
			!!req.body,
		);

		if (process.env.CF_DEBUG_TRAFFIC === "true") {
			log.info("🔍 RESPONSE DETAILS (no account):");
			log.info(`Status: ${response.status} ${response.statusText}`);
			log.info("Headers:", Object.fromEntries(response.headers.entries()));
		}

		return forwardToClient(
			{
				requestId: requestMeta.id,
				method: req.method,
				path: url.pathname,
				account: null,
				requestHeaders: req.headers,
				requestBody: requestBodyBuffer,
				response,
				timestamp: requestMeta.timestamp,
				retryAttempt: 0,
				failoverAttempts: 0,
				agentUsed: requestMeta.agentUsed,
			},
			ctx,
		);
	} catch (error) {
		logError(error, log);
		throw new ProviderError(
			ERROR_MESSAGES.UNAUTHENTICATED_FAILED,
			ctx.provider.name,
			502,
			{
				originalError: error instanceof Error ? error.message : String(error),
			},
		);
	}
}

/**
 * Attempts to proxy a request with a specific account
 * @param req - The incoming request
 * @param url - The parsed URL
 * @param account - The account to use
 * @param requestMeta - Request metadata
 * @param requestBodyBuffer - Buffered request body
 * @param createBodyStream - Function to create body stream
 * @param failoverAttempts - Number of failover attempts
 * @param ctx - The proxy context
 * @returns Promise resolving to response or null if failed
 */
export async function proxyWithAccount(
	req: Request,
	url: URL,
	account: Account,
	requestMeta: RequestMeta,
	requestBodyBuffer: ArrayBuffer | null,
	createBodyStream: () => ReadableStream<Uint8Array> | undefined,
	failoverAttempts: number,
	ctx: ProxyContext,
): Promise<Response | null> {
	try {
		log.info(`Attempting request with account: ${account.name}`);

		// Log account details for debugging
		const isMaxAccount = !account.api_key && account.refresh_token;
		const isClaudeCodeRequest =
			req.headers.get("x-app") === "cli" ||
			req.headers.get("user-agent")?.includes("claude-cli");

		log.debug(
			`Account type: ${isMaxAccount ? "Max (OAuth)" : "Console (API Key)"}`,
		);
		log.debug(`Claude Code request: ${isClaudeCodeRequest}`);
		log.debug(`Request path: ${url.pathname}`);

		// Special handling for Claude Code with Max accounts
		if (
			isClaudeCodeRequest &&
			isMaxAccount &&
			url.pathname.startsWith("/v1/")
		) {
			log.warn(
				`Claude Code detected with Max account on standard API endpoint`,
			);
			log.info(
				`Max accounts use OAuth tokens which are not supported by standard API endpoints`,
			);
			log.info(
				`Unfortunately, Claude Code's internal OAuth endpoints are not publicly documented`,
			);
			log.info(`Options:`);
			log.info(
				`1. Add a console mode account: bun run ccflare --add-account api-account --mode console`,
			);
			log.info(
				`2. Use Claude Code directly without proxy: unset ANTHROPIC_BASE_URL`,
			);

			// Return a more detailed error response
			const _errorResponse = {
				type: "error",
				error: {
					type: "authentication_error",
					message:
						"Claude Code OAuth tokens cannot be used with standard API endpoints. The internal endpoints used by Claude Code are not publicly documented. Please either add a console mode account or use Claude Code directly without the proxy.",
				},
			};

			// Still forward the request to see the actual error
			log.info(
				`Forwarding request anyway to capture the actual API response...`,
			);
		}

		// Always use ccflare's authentication
		const accessToken = await getValidAccessToken(account, ctx);
		const apiKey = account.api_key || undefined;

		if (isClaudeCodeRequest && isMaxAccount) {
			log.info(`Using Max account OAuth token for Claude Code request`);
			log.info(
				`Access token: ${accessToken ? `Bearer ${accessToken.substring(0, 10)}...` : "empty"}`,
			);
			log.info(`API key: ${apiKey ? "present" : "none"}`);
		}

		// Prepare request
		const headers = ctx.provider.prepareHeaders(
			req.headers,
			accessToken,
			apiKey,
		);
		const targetUrl = ctx.provider.buildUrl(url.pathname, url.search);

		// Make the request
		if (process.env.CF_DEBUG_TRAFFIC === "true") {
			log.info("🔍 REQUEST DETAILS (with account):");
			log.info(`URL: ${targetUrl}`);
			log.info(`Method: ${req.method}`);
			log.info(
				`Account: ${account.name} (${account.api_key ? "API Key" : "OAuth"})`,
			);
			log.info("Headers:", Object.fromEntries(headers.entries()));
		}

		const response = await makeProxyRequest(
			targetUrl,
			req.method,
			headers,
			createBodyStream,
			!!req.body,
		);

		if (process.env.CF_DEBUG_TRAFFIC === "true") {
			log.info("🔍 RESPONSE DETAILS:");
			log.info(`Status: ${response.status} ${response.statusText}`);
			log.info("Headers:", Object.fromEntries(response.headers.entries()));
		}

		// Log response status for debugging
		log.info(
			`Response status: ${response.status} for account: ${account.name}`,
		);
		if (response.status === 401 || response.status === 403) {
			const errorHeader = response.headers.get("content-type");
			if (errorHeader?.includes("json")) {
				try {
					const errorBody = await response.clone().text();
					log.warn(`Authentication error response: ${errorBody}`);
				} catch {
					// Ignore if we can't read the body
				}
			}
		}

		// Process response and check for rate limit
		const isRateLimited = processProxyResponse(response, account, ctx);
		if (isRateLimited) {
			return null; // Signal to try next account
		}

		// Forward response to client
		return forwardToClient(
			{
				requestId: requestMeta.id,
				method: req.method,
				path: url.pathname,
				account,
				requestHeaders: req.headers,
				requestBody: requestBodyBuffer,
				response,
				timestamp: requestMeta.timestamp,
				retryAttempt: 0,
				failoverAttempts,
				agentUsed: requestMeta.agentUsed,
			},
			ctx,
		);
	} catch (err) {
		handleProxyError(err, account, log);
		return null;
	}
}
