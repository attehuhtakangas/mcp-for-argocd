import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createServer } from './server.js';

vi.mock('../argocd/client.js', () => {
  const instances: unknown[] = [];
  class ArgoCDClient {
    baseUrl: string;
    apiToken: string;
    listApplications: ReturnType<typeof vi.fn>;
    // listApplications is built in the constructor body, not as a class-field
    // initializer -- field initializers run before the constructor body, so
    // `this.baseUrl` would still be undefined at that point and every
    // instance's mock would resolve to the same wrong 'from-undefined' value.
    constructor(opts: { baseUrl: string; apiToken: string; tokenRefreshProvider?: unknown }) {
      this.baseUrl = opts.baseUrl;
      this.apiToken = opts.apiToken;
      this.listApplications = vi
        .fn()
        .mockResolvedValue([{ metadata: { name: 'from-' + this.baseUrl } }]);
      instances.push(this);
    }
  }
  return { ArgoCDClient, __instances: instances };
});

vi.mock('../auth/token-refresh.js', () => ({
  createTokenRefreshProvider: vi.fn().mockReturnValue({ refreshToken: vi.fn() })
}));

type ToolCallResult = {
  isError: boolean;
  content: Array<{ type: string; text: string }>;
};

type ServerWithRegisteredTools = {
  _registeredTools: Record<string, { handler: (...args: unknown[]) => Promise<ToolCallResult> }>;
};

function getTool(server: ReturnType<typeof createServer>, name: string) {
  return (server as unknown as ServerWithRegisteredTools)._registeredTools[name];
}

describe('Server dynamic argocdBaseUrl targeting', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('uses the default client when argocdBaseUrl is omitted', async () => {
    const server = createServer({
      argocdBaseUrl: 'https://default.example.com',
      argocdApiToken: 'default-token',
      isAuthenticated: true
    });

    const tool = getTool(server, 'list_applications');
    const result = await tool.handler({}, {});

    expect(result.isError).toBe(false);
    const body = JSON.parse(result.content[0].text);
    expect(body[0].metadata.name).toBe('from-https://default.example.com');
  });

  it('resolves and uses a different client when argocdBaseUrl is provided', async () => {
    const resolveServerAuth = vi.fn().mockResolvedValue({
      baseUrl: 'https://mouser.example.com',
      apiToken: 'mouser-token'
    });
    const server = createServer({
      argocdBaseUrl: 'https://default.example.com',
      argocdApiToken: 'default-token',
      isAuthenticated: true,
      resolveServerAuth
    });

    const tool = getTool(server, 'list_applications');
    const result = await tool.handler({ argocdBaseUrl: 'https://mouser.example.com' }, {});

    expect(resolveServerAuth).toHaveBeenCalledWith('https://mouser.example.com');
    expect(result.isError).toBe(false);
    const body = JSON.parse(result.content[0].text);
    expect(body[0].metadata.name).toBe('from-https://mouser.example.com');
  });

  it('caches the resolved client so a second call with the same argocdBaseUrl does not re-resolve', async () => {
    const resolveServerAuth = vi.fn().mockResolvedValue({
      baseUrl: 'https://mouser.example.com',
      apiToken: 'mouser-token'
    });
    const server = createServer({
      argocdBaseUrl: 'https://default.example.com',
      argocdApiToken: 'default-token',
      isAuthenticated: true,
      resolveServerAuth
    });

    const tool = getTool(server, 'list_applications');
    await tool.handler({ argocdBaseUrl: 'https://mouser.example.com' }, {});
    await tool.handler({ argocdBaseUrl: 'https://mouser.example.com' }, {});

    expect(resolveServerAuth).toHaveBeenCalledTimes(1);
  });

  it('errors, naming the login command, when argocdBaseUrl has no stored login', async () => {
    const resolveServerAuth = vi.fn().mockResolvedValue(null);
    const server = createServer({
      argocdBaseUrl: 'https://default.example.com',
      argocdApiToken: 'default-token',
      isAuthenticated: true,
      resolveServerAuth
    });

    const tool = getTool(server, 'list_applications');
    const result = await tool.handler({ argocdBaseUrl: 'https://costco.example.com' }, {});

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('argocd-mcp login https://costco.example.com');
  });

  it('errors when argocdBaseUrl is given but the server has no resolveServerAuth wired', async () => {
    const server = createServer({
      argocdBaseUrl: 'https://default.example.com',
      argocdApiToken: 'default-token',
      isAuthenticated: true
    });

    const tool = getTool(server, 'list_applications');
    const result = await tool.handler({ argocdBaseUrl: 'https://costco.example.com' }, {});

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain(
      'does not support targeting a different ArgoCD base URL'
    );
  });

  it('does not require default authentication when argocdBaseUrl is provided', async () => {
    const resolveServerAuth = vi.fn().mockResolvedValue({
      baseUrl: 'https://mouser.example.com',
      apiToken: 'mouser-token'
    });
    const server = createServer({
      argocdBaseUrl: '',
      argocdApiToken: '',
      isAuthenticated: false,
      resolveServerAuth
    });

    const tool = getTool(server, 'list_applications');
    const result = await tool.handler({ argocdBaseUrl: 'https://mouser.example.com' }, {});

    expect(result.isError).toBe(false);
  });

  it('still refuses an unauthenticated call when argocdBaseUrl is omitted', async () => {
    const server = createServer({
      argocdBaseUrl: '',
      argocdApiToken: '',
      isAuthenticated: false
    });

    const tool = getTool(server, 'list_applications');
    const result = await tool.handler({}, {});

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Not authenticated');
  });
});
