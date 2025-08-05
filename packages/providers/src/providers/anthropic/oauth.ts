import { OAuthError } from "@ccflare/core";
import type {
	OAuthProvider,
	OAuthProviderConfig,
	PKCEChallenge,
	TokenResult,
} from "../../types";

export class AnthropicOAuthProvider implements OAuthProvider {
	getOAuthConfig(mode: "console" | "max" = "console"): OAuthProviderConfig {
		const baseUrl =
			mode === "console"
				? "https://console.anthropic.com"
				: "https://claude.ai";

		return {
			authorizeUrl: `${baseUrl}/oauth/authorize`,
			tokenUrl: "https://console.anthropic.com/v1/oauth/token",
			clientId: "", // Will be passed from config
			scopes: ["org:create_api_key", "user:profile", "user:inference"],
			redirectUri: "https://console.anthropic.com/oauth/code/callback",
			mode,
		};
	}

	generateAuthUrl(
		config: OAuthProviderConfig,
		pkce: PKCEChallenge,
	): { url: string; state: string } {
		const url = new URL(config.authorizeUrl);
		url.searchParams.set("code", "true");
		url.searchParams.set("client_id", config.clientId);
		url.searchParams.set("response_type", "code");
		url.searchParams.set("redirect_uri", config.redirectUri);
		url.searchParams.set("scope", config.scopes.join(" "));
		url.searchParams.set("code_challenge", pkce.challenge);
		url.searchParams.set("code_challenge_method", "S256");
		// Generate a separate state parameter (different from verifier)
		const state = crypto.randomUUID().replace(/-/g, "");
		url.searchParams.set("state", state);
		return { url: url.toString(), state };
	}

	async exchangeCode(
		code: string,
		verifier: string,
		config: OAuthProviderConfig,
		stateParam?: string,
	): Promise<TokenResult> {
		// Handle both "code#state" format and plain code
		let authCode = code;
		let extractedState = "";

		if (code.includes("#")) {
			const splits = code.split("#");
			authCode = splits[0];
			extractedState = splits[1] || "";
		}

		// Use the passed state parameter if provided, otherwise use extracted state
		const finalState = stateParam || extractedState;

		// Log for debugging
		console.log("OAuth token exchange:", {
			tokenUrl: config.tokenUrl,
			codeLength: authCode.length,
			hasState: !!finalState,
			stateLength: finalState?.length,
			clientId: config.clientId,
		});

		// Build request body - Anthropic expects JSON!
		const requestBody = {
			grant_type: "authorization_code",
			code: authCode,
			redirect_uri: config.redirectUri,
			client_id: config.clientId,
			code_verifier: verifier,
			state: finalState,
		};

		console.log("OAuth request body:", JSON.stringify(requestBody, null, 2));

		const response = await fetch(config.tokenUrl, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Accept: "application/json, text/plain, */*",
				"User-Agent": "axios/1.8.4", // Match what Claude CLI sends
			},
			body: JSON.stringify(requestBody),
		});

		if (!response.ok) {
			let errorDetails: { error?: string; error_description?: string } | null =
				null;
			let rawError = "";
			try {
				const text = await response.text();
				rawError = text;
				errorDetails = JSON.parse(text);
			} catch {
				// Failed to parse error response
				console.error("Raw error response:", rawError);
			}

			console.error("OAuth exchange failed:", {
				status: response.status,
				statusText: response.statusText,
				errorDetails,
			});

			const errorMessage =
				errorDetails?.error_description ||
				errorDetails?.error ||
				response.statusText ||
				"OAuth token exchange failed";

			throw new OAuthError(errorMessage, "anthropic", errorDetails?.error);
		}

		const json = (await response.json()) as {
			refresh_token: string;
			access_token: string;
			expires_in: number;
		};

		return {
			refreshToken: json.refresh_token,
			accessToken: json.access_token,
			expiresAt: Date.now() + json.expires_in * 1000,
		};
	}
}
