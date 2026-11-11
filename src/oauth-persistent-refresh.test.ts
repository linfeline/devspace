import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";
import { AccessDeniedError, InvalidGrantError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import { SingleUserOAuthProvider } from "./oauth-provider.js";
import type { OAuthConfig } from "./oauth-provider.js";
import { SqliteOAuthStore } from "./oauth-store.js";

const baseConfig: OAuthConfig = {
  ownerToken: "test-owner-token-that-is-long-enough",
  accessTokenTtlSeconds: 3600,
  refreshTokenTtlSeconds: 2592000,
  scopes: ["devspace", "read"],
  allowedResourceUrls: ["https://tunnel.example.com/v1/mcp/tunnel_123"],
  allowedRedirectHosts: ["chatgpt.com"],
};

const serverUrl = new URL("https://agent.example.com/mcp");
const resource = new URL(baseConfig.allowedResourceUrls[0]!);
const otherResource = new URL("https://other.example.com/mcp");
const redirectUri = "https://chatgpt.com/connector_platform_oauth_redirect";
const realDateNow = Date.now;
const baseSeconds = 2_000_000_000;

test("a listed client keeps the same refresh token and extends its expiry", async (t) => {
  const root = await fixture(t);
  const stateDir = join(root, "reuse");
  setNowSeconds(baseSeconds);

  const { client, tokens } = await issueInitialTokens(stateDir, baseConfig);
  const config = { ...baseConfig, persistentRefreshTokenClients: [client.client_id] };
  const provider = new SingleUserOAuthProvider(config, serverUrl, stateDir);

  try {
    setNowSeconds(baseSeconds + 5);
    const refreshed = await provider.exchangeRefreshToken(client, tokens.refresh_token);

    assert.equal(refreshed.refresh_token, tokens.refresh_token, "the client receives the token it already stored");
    assert.notEqual(refreshed.access_token, tokens.access_token, "access tokens still rotate");
    assert.equal((await provider.verifyAccessToken(refreshed.access_token)).clientId, client.client_id);
    assert.equal(readRefreshExpiry(stateDir, tokens.refresh_token), baseSeconds + 5 + config.refreshTokenTtlSeconds);

    const [left, right] = await Promise.all([
      provider.exchangeRefreshToken(client, tokens.refresh_token),
      provider.exchangeRefreshToken(client, tokens.refresh_token),
    ]);

    assert.equal(left.refresh_token, tokens.refresh_token, "concurrent refreshes share the stable token");
    assert.equal(right.refresh_token, tokens.refresh_token);
    assert.equal(readRefreshExpiry(stateDir, tokens.refresh_token), baseSeconds + 5 + config.refreshTokenTtlSeconds);

    const reopened = new SingleUserOAuthProvider(config, serverUrl, stateDir);

    try {
      const afterRestart = await reopened.exchangeRefreshToken(client, tokens.refresh_token);

      assert.equal(afterRestart.refresh_token, tokens.refresh_token, "reuse survives a restart");
      await reopened.revokeToken(client, { token: tokens.refresh_token });
      await assert.rejects(
        reopened.exchangeRefreshToken(client, tokens.refresh_token),
        InvalidGrantError,
        "revoking the stable token still disconnects the client",
      );
    } finally {
      reopened.close();
    }
  } finally {
    provider.close();
    Date.now = realDateNow;
  }
});

test("clients absent from the persistent list keep rotating", async (t) => {
  const root = await fixture(t);
  const stateDir = join(root, "rotate");
  setNowSeconds(baseSeconds);

  const { client, tokens } = await issueInitialTokens(stateDir, baseConfig);

  const provider = new SingleUserOAuthProvider(
    { ...baseConfig, persistentRefreshTokenClients: ["devspace-another-client"] },
    serverUrl,
    stateDir,
  );

  try {
    const refreshed = await provider.exchangeRefreshToken(client, tokens.refresh_token);

    assert.notEqual(refreshed.refresh_token, tokens.refresh_token);
    await assert.rejects(provider.exchangeRefreshToken(client, tokens.refresh_token), InvalidGrantError);
    assert.ok(refreshed.refresh_token);
  } finally {
    provider.close();
    Date.now = realDateNow;
  }
});

test("persistent reuse keeps the client, scope, and resource checks", async (t) => {
  const root = await fixture(t);
  const stateDir = join(root, "policy");
  const provider = new SingleUserOAuthProvider(baseConfig, serverUrl, stateDir);

  try {
    const { client, tokens } = await issueInitialTokens(stateDir, baseConfig);
    const otherClient = await provider.clientsStore.registerClient?.({ redirect_uris: [redirectUri] });

    assert.ok(otherClient);

    const scoped = new SingleUserOAuthProvider(
      { ...baseConfig, persistentRefreshTokenClients: [client.client_id] },
      serverUrl,
      stateDir,
    );

    try {
      await assert.rejects(scoped.exchangeRefreshToken(otherClient, tokens.refresh_token), InvalidGrantError);
      await assert.rejects(
        scoped.exchangeRefreshToken(client, tokens.refresh_token, ["write"]),
        AccessDeniedError,
      );
      await assert.rejects(
        scoped.exchangeRefreshToken(client, tokens.refresh_token, undefined, otherResource),
        InvalidGrantError,
      );
    } finally {
      scoped.close();
    }
  } finally {
    provider.close();
    Date.now = realDateNow;
  }
});

test("an expired persistent refresh token cannot be revived", async (t) => {
  const root = await fixture(t);
  const stateDir = join(root, "expired");
  setNowSeconds(baseSeconds);

  const { client, tokens } = await issueInitialTokens(stateDir, {
    ...baseConfig,
    refreshTokenTtlSeconds: 30,
  });

  const provider = new SingleUserOAuthProvider(
    { ...baseConfig, refreshTokenTtlSeconds: 30, persistentRefreshTokenClients: [client.client_id] },
    serverUrl,
    stateDir,
  );

  try {
    setNowSeconds(baseSeconds + 31);
    await assert.rejects(provider.exchangeRefreshToken(client, tokens.refresh_token), InvalidGrantError);
  } finally {
    provider.close();
    Date.now = realDateNow;
  }
});

async function fixture(t: TestContext): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "devspace-oauth-persistent-test-"));
  t.after(async () => {
    Date.now = realDateNow;
    await rm(root, { recursive: true, force: true });
  });

  return root;
}

async function issueInitialTokens(stateDir: string, config: OAuthConfig) {
  const provider = new SingleUserOAuthProvider(config, serverUrl, stateDir);

  try {
    const client = await provider.clientsStore.registerClient?.({
      redirect_uris: [redirectUri],
      client_name: "Test client",
    });

    assert.ok(client);
    const code = `test-code-${Math.random()}`;
    provider["codes"].set(code, {
      clientId: client.client_id,
      params: {
        redirectUri,
        codeChallenge: "challenge",
        scopes: ["devspace"],
        resource,
      },
      expiresAtMs: Date.now() + 60_000,
    });
    const tokens = await provider.exchangeAuthorizationCode(client, code, undefined, redirectUri, resource);
    assert.ok(tokens.refresh_token);

    return { client, tokens: { ...tokens, refresh_token: tokens.refresh_token } };
  } finally {
    provider.close();
  }
}

function readRefreshExpiry(stateDir: string, token: string): number | undefined {
  const store = new SqliteOAuthStore(stateDir);

  try {
    return store.getRefreshToken(hashToken(token))?.expiresAt;
  } finally {
    store.close();
  }
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("base64url");
}

function setNowSeconds(seconds: number): void {
  Date.now = () => seconds * 1000;
}
