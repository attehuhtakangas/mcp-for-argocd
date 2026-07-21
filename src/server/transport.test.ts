import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { OIDCConfig } from '../auth/types.js';

const mockCreateServer = vi.fn().mockReturnValue({ connect: vi.fn().mockResolvedValue(undefined) });

vi.mock('./server.js', () => ({
  createServer: (...args: unknown[]) => mockCreateServer(...args)
}));

vi.mock('@modelcontextprotocol/sdk/server/stdio.js', () => ({
  StdioServerTransport: vi.fn()
}));

vi.mock('../auth/token-store.js', () => ({
  getDefaultServer: vi.fn().mockResolvedValue(null),
  loadToken: vi.fn(),
  isTokenExpired: vi.fn(),
  saveToken: vi.fn()
}));

vi.mock('../auth/token-refresh.js', () => ({
  createTokenRefreshProvider: vi.fn()
}));

vi.mock('../logging/logging.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() }
}));

describe('connectStdioTransport resolveServerAuth wiring', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.ARGOCD_BASE_URL;
    delete process.env.ARGOCD_API_TOKEN;
  });

  it('passes a resolveServerAuth function to createServer', async () => {
    const { connectStdioTransport } = await import('./transport.js');
    await connectStdioTransport();

    expect(mockCreateServer).toHaveBeenCalledTimes(1);
    const serverInfo = mockCreateServer.mock.calls[0][0];
    expect(typeof serverInfo.resolveServerAuth).toBe('function');
  });

  it('resolveServerAuth returns null for a server with no stored token', async () => {
    const { connectStdioTransport } = await import('./transport.js');
    await connectStdioTransport();

    const serverInfo = mockCreateServer.mock.calls[0][0];
    const result = await serverInfo.resolveServerAuth('https://unknown.example.com');
    expect(result).toBeNull();
  });

  it('resolveServerAuth returns baseUrl/apiToken for a server with a valid stored token', async () => {
    const { loadToken, isTokenExpired } = await import('../auth/token-store.js');
    const oidcConfig: OIDCConfig = {
      issuer: 'https://dex.example.com',
      clientID: 'argo-cd-cli',
      scopes: ['openid', 'profile', 'email'],
      enablePKCEAuthentication: true,
      useDex: true
    };
    vi.mocked(loadToken).mockResolvedValue({
      serverUrl: 'https://mouser.example.com',
      token: { accessToken: 'access', idToken: 'id-token' },
      oidcConfig,
      storedAt: Date.now()
    });
    vi.mocked(isTokenExpired).mockReturnValue(false);

    const { connectStdioTransport } = await import('./transport.js');
    await connectStdioTransport();

    const serverInfo = mockCreateServer.mock.calls[0][0];
    const result = await serverInfo.resolveServerAuth('https://mouser.example.com');
    expect(result).toEqual({ baseUrl: 'https://mouser.example.com', apiToken: 'id-token' });
  });
});
