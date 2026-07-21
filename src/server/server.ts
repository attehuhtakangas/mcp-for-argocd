import { McpServer, ToolCallback } from '@modelcontextprotocol/sdk/server/mcp.js';

import packageJSON from '../../package.json' with { type: 'json' };
import { ArgoCDClient } from '../argocd/client.js';
import { z, ZodRawShape } from 'zod';
import { V1alpha1Application, V1alpha1ResourceResult } from '../types/argocd-types.js';
import {
  ApplicationNamespaceSchema,
  ApplicationSchema,
  ResourceRefSchema
} from '../shared/models/schema.js';
import type { TokenRefreshProvider } from '../auth/token-refresh.js';
import { createTokenRefreshProvider } from '../auth/token-refresh.js';

export type ResolvedServerAuth = { baseUrl: string; apiToken: string };

type ServerInfo = {
  argocdBaseUrl: string;
  argocdApiToken: string;
  tokenRefreshProvider?: TokenRefreshProvider;
  isAuthenticated?: boolean;
  // Looks up SSO-stored credentials for an ArgoCD base URL other than this
  // server's default -- e.g. a second ArgoCD instance logged into via
  // `argocd-mcp login <url>`. Only wired on the stdio transport today (see
  // connectStdioTransport); when omitted, tools cannot target another server
  // and a caller-supplied argocdBaseUrl fails outright.
  resolveServerAuth?: (serverUrl: string) => Promise<ResolvedServerAuth | null>;
};

// Per-call argument every tool accepts to target a different ArgoCD instance
// than this server's configured default.
const dynamicServerArgsSchema = {
  argocdBaseUrl: z
    .string()
    .optional()
    .describe(
      "ArgoCD base URL to target for this call instead of the server default -- e.g. another ArgoCD instance you have already logged into via `argocd-mcp login <url>`. Omit to use this server's configured default."
    )
} satisfies ZodRawShape;

type DynamicServerArgs = { argocdBaseUrl?: string };

export class Server extends McpServer {
  private argocdClient: ArgoCDClient;
  private isAuthenticated: boolean;
  private resolveServerAuth?: (serverUrl: string) => Promise<ResolvedServerAuth | null>;
  // Caches clients built for a caller-supplied argocdBaseUrl, keyed by that
  // URL, so a long session doesn't re-resolve on every call. Each cached
  // client gets its own tokenRefreshProvider, so it self-refreshes on
  // staleness exactly like the default client does -- no separate expiry
  // check is needed here on a cache hit.
  private dynamicClientCache = new Map<string, ArgoCDClient>();

  constructor(serverInfo: ServerInfo) {
    super({
      name: packageJSON.name,
      version: packageJSON.version
    });
    this.isAuthenticated = serverInfo.isAuthenticated ?? true;
    this.resolveServerAuth = serverInfo.resolveServerAuth;
    this.argocdClient = new ArgoCDClient({
      baseUrl: serverInfo.argocdBaseUrl,
      apiToken: serverInfo.argocdApiToken,
      tokenRefreshProvider: serverInfo.tokenRefreshProvider
    });

    const isReadOnly =
      String(process.env.MCP_READ_ONLY ?? '')
        .trim()
        .toLowerCase() === 'true';

    // Always register read/query tools
    this.addJsonOutputTool(
      'list_applications',
      'list_applications returns list of applications',
      {
        search: z
          .string()
          .optional()
          .describe(
            'Search applications by name. This is a partial match on the application name and does not support glob patterns (e.g. "*"). Optional.'
          ),
        limit: z
          .number()
          .int()
          .positive()
          .optional()
          .describe(
            'Maximum number of applications to return. Use this to reduce token usage when there are many applications. Optional.'
          ),
        offset: z
          .number()
          .int()
          .min(0)
          .optional()
          .describe(
            'Number of applications to skip before returning results. Use with limit for pagination. Optional.'
          )
      },
      async ({ search, limit, offset }, client) =>
        await client.listApplications({
          search: search ?? undefined,
          limit,
          offset
        })
    );
    this.addJsonOutputTool(
      'get_application',
      'get_application returns application by application name. Optionally specify the application namespace to get applications from non-default namespaces.',
      {
        applicationName: z.string(),
        applicationNamespace: ApplicationNamespaceSchema.optional()
      },
      async ({ applicationName, applicationNamespace }, client) =>
        await client.getApplication(applicationName, applicationNamespace)
    );
    this.addJsonOutputTool(
      'get_application_resource_tree',
      'get_application_resource_tree returns resource tree for application by application name',
      { applicationName: z.string() },
      async ({ applicationName }, client) =>
        await client.getApplicationResourceTree(applicationName)
    );
    this.addJsonOutputTool(
      'get_application_managed_resources',
      'get_application_managed_resources returns managed resources for application by application name with optional filtering. Use filters to avoid token limits with large applications. Examples: kind="ConfigMap" for config maps only, namespace="production" for specific namespace, or combine multiple filters.',
      {
        applicationName: z.string(),
        kind: z
          .string()
          .optional()
          .describe(
            'Filter by Kubernetes resource kind (e.g., "ConfigMap", "Secret", "Deployment")'
          ),
        namespace: z.string().optional().describe('Filter by Kubernetes namespace'),
        name: z.string().optional().describe('Filter by resource name'),
        version: z.string().optional().describe('Filter by resource API version'),
        group: z.string().optional().describe('Filter by API group'),
        appNamespace: z.string().optional().describe('Filter by Argo CD application namespace'),
        project: z.string().optional().describe('Filter by Argo CD project')
      },
      async (
        { applicationName, kind, namespace, name, version, group, appNamespace, project },
        client
      ) => {
        const filters = {
          ...(kind && { kind }),
          ...(namespace && { namespace }),
          ...(name && { name }),
          ...(version && { version }),
          ...(group && { group }),
          ...(appNamespace && { appNamespace }),
          ...(project && { project })
        };
        return await client.getApplicationManagedResources(
          applicationName,
          Object.keys(filters).length > 0 ? filters : undefined
        );
      }
    );
    this.addJsonOutputTool(
      'get_application_workload_logs',
      'get_application_workload_logs returns logs for application workload (Deployment, StatefulSet, Pod, etc.) by application name and resource ref and optionally container name',
      {
        applicationName: z.string(),
        applicationNamespace: ApplicationNamespaceSchema,
        resourceRef: ResourceRefSchema,
        container: z.string()
      },
      async ({ applicationName, applicationNamespace, resourceRef, container }, client) =>
        await client.getWorkloadLogs(
          applicationName,
          applicationNamespace,
          resourceRef as V1alpha1ResourceResult,
          container
        )
    );
    this.addJsonOutputTool(
      'get_application_events',
      'get_application_events returns events for application by application name',
      { applicationName: z.string() },
      async ({ applicationName }, client) => await client.getApplicationEvents(applicationName)
    );
    this.addJsonOutputTool(
      'get_resource_events',
      'get_resource_events returns events for a resource that is managed by an application',
      {
        applicationName: z.string(),
        applicationNamespace: ApplicationNamespaceSchema,
        resourceUID: z.string(),
        resourceNamespace: z.string(),
        resourceName: z.string()
      },
      async (
        { applicationName, applicationNamespace, resourceUID, resourceNamespace, resourceName },
        client
      ) =>
        await client.getResourceEvents(
          applicationName,
          applicationNamespace,
          resourceUID,
          resourceNamespace,
          resourceName
        )
    );
    this.addJsonOutputTool(
      'get_resources',
      'get_resources return manifests for resources specified by resourceRefs. If resourceRefs is empty or not provided, fetches all resources managed by the application.',
      {
        applicationName: z.string(),
        applicationNamespace: ApplicationNamespaceSchema,
        resourceRefs: ResourceRefSchema.array().optional()
      },
      async ({ applicationName, applicationNamespace, resourceRefs }, client) => {
        let refs = resourceRefs || [];
        if (refs.length === 0) {
          const tree = await client.getApplicationResourceTree(applicationName);
          refs =
            tree.nodes?.map((node) => ({
              uid: node.uid!,
              version: node.version!,
              group: node.group!,
              kind: node.kind!,
              name: node.name!,
              namespace: node.namespace!
            })) || [];
        }
        return Promise.all(
          refs.map((ref) => client.getResource(applicationName, applicationNamespace, ref))
        );
      }
    );
    this.addJsonOutputTool(
      'get_resource_actions',
      'get_resource_actions returns actions for a resource that is managed by an application',
      {
        applicationName: z.string(),
        applicationNamespace: ApplicationNamespaceSchema,
        resourceRef: ResourceRefSchema
      },
      async ({ applicationName, applicationNamespace, resourceRef }, client) =>
        await client.getResourceActions(
          applicationName,
          applicationNamespace,
          resourceRef as V1alpha1ResourceResult
        )
    );

    // Only register modification tools if not in read-only mode
    if (!isReadOnly) {
      this.addJsonOutputTool(
        'create_application',
        'create_application creates a new ArgoCD application in the specified namespace. The application.metadata.namespace field determines where the Application resource will be created (e.g., "argocd", "argocd-apps", or any custom namespace).',
        { application: ApplicationSchema },
        async ({ application }, client) =>
          await client.createApplication(application as V1alpha1Application)
      );
      this.addJsonOutputTool(
        'update_application',
        'update_application updates application',
        { applicationName: z.string(), application: ApplicationSchema },
        async ({ applicationName, application }, client) =>
          await client.updateApplication(applicationName, application as V1alpha1Application)
      );
      this.addJsonOutputTool(
        'delete_application',
        'delete_application deletes application. Specify applicationNamespace if the application is in a non-default namespace to avoid permission errors.',
        {
          applicationName: z.string(),
          applicationNamespace: ApplicationNamespaceSchema.optional().describe(
            'The namespace where the application is located. Required if application is not in the default namespace.'
          ),
          cascade: z
            .boolean()
            .optional()
            .describe('Whether to cascade the deletion to child resources'),
          propagationPolicy: z
            .string()
            .optional()
            .describe('Deletion propagation policy (e.g., "Foreground", "Background", "Orphan")')
        },
        async ({ applicationName, applicationNamespace, cascade, propagationPolicy }, client) => {
          const options: Record<string, string | boolean> = {};
          if (applicationNamespace) options.appNamespace = applicationNamespace;
          if (cascade !== undefined) options.cascade = cascade;
          if (propagationPolicy) options.propagationPolicy = propagationPolicy;

          return await client.deleteApplication(
            applicationName,
            Object.keys(options).length > 0 ? options : undefined
          );
        }
      );
      this.addJsonOutputTool(
        'sync_application',
        'sync_application syncs application. Specify applicationNamespace if the application is in a non-default namespace to avoid permission errors.',
        {
          applicationName: z.string(),
          applicationNamespace: ApplicationNamespaceSchema.optional().describe(
            'The namespace where the application is located. Required if application is not in the default namespace.'
          ),
          dryRun: z
            .boolean()
            .optional()
            .describe('Perform a dry run sync without applying changes'),
          prune: z
            .boolean()
            .optional()
            .describe('Remove resources that are no longer defined in the source'),
          revision: z
            .string()
            .optional()
            .describe('Sync to a specific revision instead of the latest'),
          syncOptions: z
            .array(z.string())
            .optional()
            .describe(
              'Additional sync options (e.g., ["CreateNamespace=true", "PrunePropagationPolicy=foreground"])'
            )
        },
        async (
          { applicationName, applicationNamespace, dryRun, prune, revision, syncOptions },
          client
        ) => {
          const options: Record<string, string | boolean | string[]> = {};
          if (applicationNamespace) options.appNamespace = applicationNamespace;
          if (dryRun !== undefined) options.dryRun = dryRun;
          if (prune !== undefined) options.prune = prune;
          if (revision) options.revision = revision;
          if (syncOptions) options.syncOptions = syncOptions;

          return await client.syncApplication(
            applicationName,
            Object.keys(options).length > 0 ? options : undefined
          );
        }
      );
      this.addJsonOutputTool(
        'run_resource_action',
        'run_resource_action runs an action on a resource',
        {
          applicationName: z.string(),
          applicationNamespace: ApplicationNamespaceSchema,
          resourceRef: ResourceRefSchema,
          action: z.string()
        },
        async ({ applicationName, applicationNamespace, resourceRef, action }, client) =>
          await client.runResourceAction(
            applicationName,
            applicationNamespace,
            resourceRef as V1alpha1ResourceResult,
            action
          )
      );
    }
  }

  // Resolves which ArgoCDClient a single tool call should use: the default
  // session client when no override is given, or a client built from
  // resolveServerAuth when one is. The default client's credential is never
  // reused for an overridden base URL -- an overridden call that can't
  // resolve its own credential fails outright rather than falling back to
  // the default, since falling back would let a caller-supplied
  // argocdBaseUrl (including one echoed back from a prompt-injected tool
  // result) reach an arbitrary host using the default session's credential.
  private async resolveClient(argocdBaseUrl: string | undefined): Promise<ArgoCDClient> {
    if (!argocdBaseUrl) {
      return this.argocdClient;
    }

    const cached = this.dynamicClientCache.get(argocdBaseUrl);
    if (cached) {
      return cached;
    }

    if (!this.resolveServerAuth) {
      throw new Error(
        'This server does not support targeting a different ArgoCD base URL per call.'
      );
    }

    const auth = await this.resolveServerAuth(argocdBaseUrl);
    if (!auth) {
      throw new Error(
        `No stored login found for "${argocdBaseUrl}". Run \`argocd-mcp login ${argocdBaseUrl}\` first.`
      );
    }

    const client = new ArgoCDClient({
      baseUrl: auth.baseUrl,
      apiToken: auth.apiToken,
      tokenRefreshProvider: createTokenRefreshProvider(auth.baseUrl)
    });
    this.dynamicClientCache.set(argocdBaseUrl, client);
    return client;
  }

  private addJsonOutputTool<Args extends ZodRawShape, T>(
    name: string,
    description: string,
    paramsSchema: Args,
    cb: (args: Parameters<ToolCallback<Args>>[0], client: ArgoCDClient) => T
  ) {
    const mergedSchema = { ...paramsSchema, ...dynamicServerArgsSchema } as ZodRawShape;
    this.tool(name, description, mergedSchema, async (...args) => {
      const allArgs = args[0] as Parameters<ToolCallback<Args>>[0] & DynamicServerArgs;
      const { argocdBaseUrl, ...toolArgs } = allArgs;

      // Check authentication before executing tool -- but only when no
      // per-call override was given. A server with no default session must
      // still be usable purely via argocdBaseUrl.
      if (!argocdBaseUrl && !this.isAuthenticated) {
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: 'Not authenticated. Please run `argocd-mcp login <server-url>` to authenticate via SSO, set ARGOCD_BASE_URL and ARGOCD_API_TOKEN environment variables, or pass argocdBaseUrl to target a server you have already logged into.'
            }
          ]
        };
      }

      try {
        const client = await this.resolveClient(argocdBaseUrl);
        const result = await cb.call(this, toolArgs as Parameters<ToolCallback<Args>>[0], client);
        return {
          isError: false,
          content: [{ type: 'text', text: JSON.stringify(result) }]
        };
      } catch (error) {
        return {
          isError: true,
          content: [{ type: 'text', text: error instanceof Error ? error.message : String(error) }]
        };
      }
    });
  }
}

export const createServer = (serverInfo: ServerInfo) => {
  return new Server(serverInfo);
};
