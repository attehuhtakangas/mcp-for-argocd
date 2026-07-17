import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ArgocdOAuthProvider } from './mcp-oauth-provider.js';

vi.mock('./settings.js', () => ({
  fetchOIDCSettings: vi.fn(),
  fetchOIDCProviderMetadata: vi.fn()
}));

vi.mock('./oauth.js', () => ({
  generateState: vi.fn().mockReturnValue('mock-upstream-state'),
  generatePKCEChallenge: vi.fn().mockReturnValue({
    codeVerifier: 'mock-verifier',
    codeChallenge: 'mock-challenge',
    codeChallengeMethod: 'S256'
  }),
  buildAuthorizationUrl: vi.fn().mockReturnValue('https://dex.example.com/auth?redirect_uri=...'),
  exchangeCodeForToken: vi.fn(),
  refreshAccessToken: vi.fn()
}));

vi.mock('../logging/logging.js', () => ({
  logger: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn()
  }
}));

import { fetchOIDCSettings, fetchOIDCProviderMetadata } from './settings.js';
import { buildAuthorizationUrl, exchangeCodeForToken, refreshAccessToken } from './oauth.js';

const mockOidcConfig = {
  issuer: 'https://dex.example.com',
  clientID: 'argo-cd-cli',
  scopes: ['openid', 'profile', 'email'],
  enablePKCEAuthentication: true,
  useDex: true
};

const mockProviderMetadata = {
  issuer: 'https://dex.example.com',
  authorization_endpoint: 'https://dex.example.com/auth',
  token_endpoint: 'https://dex.example.com/token'
};

describe('ArgocdOAuthProvider', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(fetchOIDCSettings).mockResolvedValue(mockOidcConfig);
    vi.mocked(fetchOIDCProviderMetadata).mockResolvedValue(mockProviderMetadata);
  });

  describe('constructor callbackPort', () => {
    it('should use default port 8085 for callback URL', async () => {
      const provider = new ArgocdOAuthProvider('https://argocd.example.com');
      const mockRes = { redirect: vi.fn() } as any;

      await provider.authorize(
        { client_id: 'test', client_id_issued_at: 0, redirect_uris: ['http://localhost/callback'] } as any,
        { redirectUri: 'http://localhost/callback', codeChallenge: 'challenge', state: 'client-state' } as any,
        mockRes
      );

      expect(buildAuthorizationUrl).toHaveBeenCalledWith(
        mockProviderMetadata,
        mockOidcConfig,
        'http://localhost:8085/auth/callback',
        expect.any(String),
        expect.anything()
      );
    });

    it('should use custom port for callback URL', async () => {
      const provider = new ArgocdOAuthProvider('https://argocd.example.com', 9090);
      const mockRes = { redirect: vi.fn() } as any;

      await provider.authorize(
        { client_id: 'test', client_id_issued_at: 0, redirect_uris: ['http://localhost/callback'] } as any,
        { redirectUri: 'http://localhost/callback', codeChallenge: 'challenge', state: 'client-state' } as any,
        mockRes
      );

      expect(buildAuthorizationUrl).toHaveBeenCalledWith(
        mockProviderMetadata,
        mockOidcConfig,
        'http://localhost:9090/auth/callback',
        expect.any(String),
        expect.anything()
      );
    });
  });

  describe('handleUpstreamCallback', () => {
    it('should use the callbackPort-based URL when exchanging code', async () => {
      const provider = new ArgocdOAuthProvider('https://argocd.example.com', 7070);
      const mockRes = { redirect: vi.fn() } as any;

      vi.mocked(exchangeCodeForToken).mockResolvedValue({
        accessToken: 'argocd-token',
        refreshToken: 'argocd-refresh',
        expiresAt: Date.now() + 3600000
      });

      // First, authorize to create a pending auth entry
      await provider.authorize(
        { client_id: 'test-client', client_id_issued_at: 0, redirect_uris: ['http://localhost/callback'] } as any,
        { redirectUri: 'http://localhost/callback', codeChallenge: 'challenge', state: 'client-state' } as any,
        mockRes
      );

      // Handle the callback with the upstream state
      const redirectUrl = await provider.handleUpstreamCallback('upstream-code', 'mock-upstream-state');

      expect(exchangeCodeForToken).toHaveBeenCalledWith(
        mockProviderMetadata,
        mockOidcConfig,
        'upstream-code',
        'http://localhost:7070/auth/callback',
        expect.anything()
      );

      // Should redirect to the MCP client's redirect_uri with our auth code
      expect(redirectUrl).toContain('http://localhost/callback');
      expect(redirectUrl).toContain('code=');
      expect(redirectUrl).toContain('state=client-state');
    });
  });

  describe('client registration', () => {
    it('should register and retrieve clients', async () => {
      const provider = new ArgocdOAuthProvider('https://argocd.example.com');
      const store = provider.clientsStore;

      const registered = await store.registerClient!({
        redirect_uris: ['http://localhost/callback'],
        client_name: 'Test Client'
      } as any);

      expect(registered.client_id).toBeDefined();
      expect(registered.client_name).toBe('Test Client');

      const retrieved = await store.getClient(registered.client_id);
      expect(retrieved).toEqual(registered);
    });

    it('should return undefined for unknown client', async () => {
      const provider = new ArgocdOAuthProvider('https://argocd.example.com');
      const store = provider.clientsStore;

      const result = await store.getClient('nonexistent');
      expect(result).toBeUndefined();
    });
  });

  describe('verifyAccessToken', () => {
    // Drives a real authorize -> handleUpstreamCallback -> exchangeAuthorizationCode
    // flow to get a real opaque token, rather than reaching into the class's
    // private state -- verifyAccessToken's behavior only matters in terms of
    // what a caller going through the real flow would observe.
    async function issueOpaqueToken(provider: ArgocdOAuthProvider, argocdToken: {
      idToken: string;
      refreshToken?: string;
      expiresAt?: number;
    }) {
      vi.mocked(exchangeCodeForToken).mockResolvedValue({
        accessToken: 'upstream-access-token',
        idToken: argocdToken.idToken,
        refreshToken: argocdToken.refreshToken,
        expiresAt: argocdToken.expiresAt
      });

      const mockRes = { redirect: vi.fn() } as any;
      await provider.authorize(
        { client_id: 'test-client', client_id_issued_at: 0, redirect_uris: ['http://localhost/callback'] } as any,
        { redirectUri: 'http://localhost/callback', codeChallenge: 'challenge', state: 'client-state' } as any,
        mockRes
      );
      const redirectUrl = await provider.handleUpstreamCallback('upstream-code', 'mock-upstream-state');
      const ourAuthCode = new URL(redirectUrl).searchParams.get('code')!;

      const tokens = await provider.exchangeAuthorizationCode(
        { client_id: 'test-client', client_id_issued_at: 0, redirect_uris: ['http://localhost/callback'] } as any,
        ourAuthCode
      );
      return tokens;
    }

    it('does not refresh, and reports a long-lived expiry, when the upstream token is still fresh', async () => {
      const provider = new ArgocdOAuthProvider('https://argocd.example.com');
      const tokens = await issueOpaqueToken(provider, {
        idToken: 'fresh-id-token',
        refreshToken: 'upstream-refresh-token',
        expiresAt: Date.now() + 3600_000 // fresh for another hour
      });

      const authInfo = await provider.verifyAccessToken(tokens.access_token);

      expect(refreshAccessToken).not.toHaveBeenCalled();
      expect(authInfo.extra?.argocdToken).toBe('fresh-id-token');
      // Reported expiry is the long opaque-session TTL, not the ~1hr
      // upstream expiry -- this is the actual fix: the MCP SDK's
      // requireBearerAuth 401s outright once this passes, so it must not
      // mirror the upstream token's short lifetime.
      const oneDayFromNowSeconds = Math.floor((Date.now() + 24 * 60 * 60 * 1000) / 1000);
      expect(authInfo.expiresAt).toBeGreaterThan(oneDayFromNowSeconds);
    });

    it('silently refreshes the upstream token when it is stale, without the caller doing anything', async () => {
      const provider = new ArgocdOAuthProvider('https://argocd.example.com');
      const tokens = await issueOpaqueToken(provider, {
        idToken: 'stale-id-token',
        refreshToken: 'upstream-refresh-token',
        expiresAt: Date.now() - 1000 // already expired
      });

      vi.mocked(refreshAccessToken).mockResolvedValue({
        accessToken: 'new-upstream-access-token',
        idToken: 'refreshed-id-token',
        refreshToken: 'new-upstream-refresh-token',
        expiresAt: Date.now() + 3600_000
      });

      const authInfo = await provider.verifyAccessToken(tokens.access_token);

      expect(refreshAccessToken).toHaveBeenCalledWith(
        mockProviderMetadata,
        mockOidcConfig,
        'upstream-refresh-token'
      );
      expect(authInfo.extra?.argocdToken).toBe('refreshed-id-token');

      // A second call shouldn't refresh again -- the refreshed token is now
      // fresh, so the updated state must actually be persisted, not just
      // returned once.
      vi.mocked(refreshAccessToken).mockClear();
      const secondCall = await provider.verifyAccessToken(tokens.access_token);
      expect(refreshAccessToken).not.toHaveBeenCalled();
      expect(secondCall.extra?.argocdToken).toBe('refreshed-id-token');
    });

    it('throws if the upstream token is stale and there is no refresh token', async () => {
      const provider = new ArgocdOAuthProvider('https://argocd.example.com');
      const tokens = await issueOpaqueToken(provider, {
        idToken: 'stale-id-token',
        refreshToken: undefined,
        expiresAt: Date.now() - 1000
      });

      await expect(provider.verifyAccessToken(tokens.access_token)).rejects.toThrow(/log in again/);
      expect(refreshAccessToken).not.toHaveBeenCalled();
    });

    it('propagates the error if the upstream refresh itself fails', async () => {
      const provider = new ArgocdOAuthProvider('https://argocd.example.com');
      const tokens = await issueOpaqueToken(provider, {
        idToken: 'stale-id-token',
        refreshToken: 'upstream-refresh-token',
        expiresAt: Date.now() - 1000
      });

      vi.mocked(refreshAccessToken).mockRejectedValue(new Error('refresh_token expired or revoked'));

      await expect(provider.verifyAccessToken(tokens.access_token)).rejects.toThrow('refresh_token expired or revoked');
    });

    it('throws for an unknown token', async () => {
      const provider = new ArgocdOAuthProvider('https://argocd.example.com');
      await expect(provider.verifyAccessToken('nonexistent-token')).rejects.toThrow(/Invalid or expired/);
    });
  });
});
