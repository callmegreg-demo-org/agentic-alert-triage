'use strict';

const {
  ALERT_TYPE_METADATA,
  API_VERSION,
  buildDispatchPayload,
  denyDismissalRequest,
  dispatchAgenticReview,
  getAgenticSettings,
  isStaleDismissalReviewError,
  listEnterpriseTeamMembers,
  loadConfig,
  normalizeTeamLogins,
  redactSensitiveText,
  splitRepository,
  validateEnterpriseApp,
} = require('./agentic-review');
const {
  formatDenialMessage,
  getDeterministicRules,
  validateDismissalComment,
} = require('./deterministic-review');

const MAX_ALERTS_PER_REQUEST = 100;
const MAX_ALERT_NUMBER = 2147483647;
const MAX_REQUEST_COMMENT_LENGTH = 10000;
const MAX_DELIVERY_ID_LENGTH = 128;
const DEFAULT_CACHE_SETTINGS = {
  teamMembersTtlSeconds: 300,
  controlInstallationTtlSeconds: 600,
  enterpriseInstallationTtlSeconds: 600,
  appIdentityTtlSeconds: 600,
  deliveryDedupeTtlSeconds: 900,
  deliveryDedupeMaxEntries: 1000,
};

const WEBHOOK_EVENT_METADATA = Object.fromEntries(
  Object.entries(ALERT_TYPE_METADATA).map(([alertType, metadata]) => [
    metadata.webhookEvent,
    {
      alertType,
      requestDataType: metadata.requestDataType,
    },
  ])
);
const WEBHOOK_EVENTS = Object.keys(WEBHOOK_EVENT_METADATA).map(
  (eventName) => `${eventName}.created`
);

class BoundedTtlCache {
  constructor({ ttlMs, maxEntries, now = Date.now }) {
    this.ttlMs = ttlMs;
    this.maxEntries = maxEntries;
    this.now = now;
    this.entries = new Map();
  }

  getEntry(key) {
    const entry = this.entries.get(key);
    if (!entry) return null;
    if (entry.settled && entry.expiresAt <= this.now()) {
      this.entries.delete(key);
      return null;
    }
    this.entries.delete(key);
    this.entries.set(key, entry);
    return entry;
  }

  setEntry(key, entry) {
    this.entries.set(key, entry);
    while (this.entries.size > this.maxEntries) {
      const settledKey = [...this.entries].find(
        ([, candidate]) => candidate.settled
      )?.[0];
      this.entries.delete(settledKey || this.entries.keys().next().value);
    }
  }

  createEntry(key, loader) {
    const entry = {
      settled: false,
      expiresAt: Number.POSITIVE_INFINITY,
      promise: null,
    };
    entry.promise = Promise.resolve().then(loader);
    this.setEntry(key, entry);
    entry.promise.then(
      () => {
        if (this.entries.get(key) === entry) {
          entry.settled = true;
          entry.expiresAt = this.now() + this.ttlMs;
        }
      },
      () => {
        if (this.entries.get(key) === entry) {
          this.entries.delete(key);
        }
      }
    );
    return entry;
  }

  async getOrLoad(key, loader) {
    const entry = this.getEntry(key) || this.createEntry(key, loader);
    return entry.promise;
  }

  async runOnce(key, loader) {
    const existing = this.getEntry(key);
    if (existing) {
      return { duplicate: true, value: await existing.promise };
    }

    const entry = this.createEntry(key, loader);
    return { duplicate: false, value: await entry.promise };
  }
}

function getEnabledAlertTypes(config) {
  const configured =
    config.alert_types === undefined
      ? Object.keys(ALERT_TYPE_METADATA)
      : config.alert_types;
  if (!Array.isArray(configured)) {
    throw new Error('alert_types must be an array.');
  }

  const enabled = new Set();
  for (const alertType of configured) {
    if (!Object.hasOwn(ALERT_TYPE_METADATA, alertType)) {
      throw new Error(`Unsupported alert type "${alertType}" in config.yml.`);
    }
    enabled.add(alertType);
  }
  return enabled;
}

function getBoundedConfigNumber(
  value,
  fallback,
  label,
  minimum,
  maximum
) {
  if (value === undefined) return fallback;
  if (
    !Number.isInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    throw new Error(
      `${label} must be an integer between ${minimum} and ${maximum}.`
    );
  }
  return value;
}

function getCacheSettings(config) {
  const cache = config.cache || {};
  return {
    enterpriseInstallationTtlSeconds: getBoundedConfigNumber(
      cache.enterprise_installation_ttl_seconds,
      DEFAULT_CACHE_SETTINGS.enterpriseInstallationTtlSeconds,
      'cache.enterprise_installation_ttl_seconds',
      1,
      3600
    ),
    appIdentityTtlSeconds: getBoundedConfigNumber(
      cache.app_identity_ttl_seconds,
      DEFAULT_CACHE_SETTINGS.appIdentityTtlSeconds,
      'cache.app_identity_ttl_seconds',
      1,
      3600
    ),
    teamMembersTtlSeconds: getBoundedConfigNumber(
      cache.team_members_ttl_seconds,
      DEFAULT_CACHE_SETTINGS.teamMembersTtlSeconds,
      'cache.team_members_ttl_seconds',
      1,
      3600
    ),
    controlInstallationTtlSeconds: getBoundedConfigNumber(
      cache.control_installation_ttl_seconds,
      DEFAULT_CACHE_SETTINGS.controlInstallationTtlSeconds,
      'cache.control_installation_ttl_seconds',
      1,
      3600
    ),
    deliveryDedupeTtlSeconds: getBoundedConfigNumber(
      cache.delivery_dedupe_ttl_seconds,
      DEFAULT_CACHE_SETTINGS.deliveryDedupeTtlSeconds,
      'cache.delivery_dedupe_ttl_seconds',
      1,
      3600
    ),
    deliveryDedupeMaxEntries: getBoundedConfigNumber(
      cache.delivery_dedupe_max_entries,
      DEFAULT_CACHE_SETTINGS.deliveryDedupeMaxEntries,
      'cache.delivery_dedupe_max_entries',
      1,
      10000
    ),
  };
}

function requireObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object.`);
  }
  return value;
}

function requirePositiveInteger(
  value,
  label,
  maximum = Number.MAX_SAFE_INTEGER
) {
  const normalized = Number(value);
  if (
    !Number.isSafeInteger(normalized) ||
    normalized <= 0 ||
    normalized > maximum
  ) {
    throw new Error(`Invalid ${label}.`);
  }
  return normalized;
}

function requireString(value, label, maximumLength) {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > maximumLength
  ) {
    throw new Error(`${label} must be a non-empty bounded string.`);
  }
  return value;
}

function optionalString(value, label, maximumLength) {
  if (value == null) return null;
  if (typeof value !== 'string') {
    throw new Error(`${label} must be a string when provided.`);
  }
  return value.slice(0, maximumLength);
}

function normalizeDeliveryId(value) {
  if (value == null || value === '') return null;
  const deliveryId = requireString(
    String(value),
    'Webhook delivery ID',
    MAX_DELIVERY_ID_LENGTH
  );
  if (!/^[A-Za-z0-9._:-]+$/.test(deliveryId)) {
    throw new Error('Webhook delivery ID contains unsupported characters.');
  }
  return deliveryId;
}

function validateWebhookContext(context, eventName) {
  const eventMetadata = WEBHOOK_EVENT_METADATA[eventName];
  if (!eventMetadata) {
    throw new Error(`Unsupported webhook event "${eventName}".`);
  }

  const payload = requireObject(context.payload, 'Webhook payload');
  if (payload.action !== 'created') {
    throw new Error(`Unexpected ${eventName} action. Expected "created".`);
  }

  const organization = requireObject(
    payload.organization,
    'Webhook organization'
  );
  const organizationLogin = requireString(
    organization.login,
    'Webhook organization login',
    39
  );
  if (!/^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/.test(organizationLogin)) {
    throw new Error('Webhook organization login is invalid.');
  }
  const repository = requireObject(payload.repository, 'Webhook repository');
  const repositoryFullName = requireString(
    repository.full_name,
    'Webhook repository full name',
    140
  );
  const { owner } = splitRepository(repositoryFullName);
  if (owner.toLowerCase() !== organizationLogin.toLowerCase()) {
    throw new Error(
      'Webhook repository owner does not match the webhook organization.'
    );
  }
  const repositoryId = requirePositiveInteger(
    repository.id,
    'repository ID'
  );

  const installation = requireObject(
    payload.installation,
    'Webhook installation'
  );
  const installationId = requirePositiveInteger(
    installation.id,
    'installation ID'
  );

  const sender = requireObject(payload.sender, 'Webhook sender');
  requireString(sender.login, 'Webhook sender login', 100);

  const request = requireObject(
    payload.exemption_request,
    'Webhook exemption_request'
  );
  const requestId = requirePositiveInteger(
    request.id,
    'dismissal request ID'
  );
  const requestNumber =
    eventMetadata.alertType === 'secret_scanning' && request.number === null
      ? null
      : requirePositiveInteger(
          request.number,
          'dismissal request number'
        );
  const requestRepositoryId = requirePositiveInteger(
    request.repository_id,
    'dismissal request repository ID'
  );
  if (requestRepositoryId !== repositoryId) {
    throw new Error(
      'Webhook dismissal request repository ID does not match the repository.'
    );
  }

  const requesterId = requirePositiveInteger(
    request.requester_id,
    'requester ID'
  );
  const requesterLogin = requireString(
    request.requester_login,
    'requester login',
    100
  );
  if (!/^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/.test(requesterLogin)) {
    throw new Error('Webhook requester login is invalid.');
  }

  const requestData = requireObject(
    request.exemption_request_data,
    'Webhook exemption_request_data'
  );
  if (requestData.type !== eventMetadata.requestDataType) {
    throw new Error(
      `Webhook event ${eventName} does not match exemption_request_data.type.`
    );
  }
  if (
    !Array.isArray(requestData.data) ||
    requestData.data.length === 0 ||
    requestData.data.length > MAX_ALERTS_PER_REQUEST
  ) {
    throw new Error(
      `Webhook exemption_request_data.data must contain 1-${MAX_ALERTS_PER_REQUEST} alerts.`
    );
  }

  const normalizedData = requestData.data.map((item, index) => {
    const normalizedItem = requireObject(
      item,
      `Webhook exemption_request_data.data[${index}]`
    );
    const alertNumber = requirePositiveInteger(
      normalizedItem.alert_number,
      `alert number at index ${index}`,
      MAX_ALERT_NUMBER
    );
    return {
      alert_number: alertNumber,
      ...(typeof normalizedItem.reason === 'string'
        ? { reason: normalizedItem.reason.slice(0, 500) }
        : {}),
      ...(typeof normalizedItem.secret_type === 'string'
        ? { secret_type: normalizedItem.secret_type.slice(0, 200) }
        : {}),
    };
  });
  const alertNumbers = [
    ...new Set(normalizedData.map((item) => item.alert_number)),
  ];

  const requesterComment = optionalString(
    request.requester_comment,
    'requester_comment',
    MAX_REQUEST_COMMENT_LENGTH
  );

  return {
    organization: organizationLogin,
    repository: repositoryFullName,
    repositoryId,
    installationId,
    deliveryId: normalizeDeliveryId(context.id),
    alertType: eventMetadata.alertType,
    alertNumbers,
    dismissalRequest: {
      id: requestId,
      number: requestNumber,
      repository_id: requestRepositoryId,
      requester_id: requesterId,
      requester_login: requesterLogin,
      request_type: requireString(
        request.request_type,
        'request_type',
        100
      ),
      exemption_request_data: {
        type: requestData.type,
        data: normalizedData,
      },
      resource_identifier: optionalString(
        request.resource_identifier == null
          ? null
          : String(request.resource_identifier),
        'resource_identifier',
        500
      ),
      status: requireString(request.status, 'request status', 50),
      requester_comment: requesterComment,
      expires_at: optionalString(request.expires_at, 'expires_at', 100),
      created_at: optionalString(request.created_at, 'created_at', 100),
      html_url: optionalString(request.html_url, 'html_url', 500),
    },
  };
}

function redactWebhookPayloadForLogging(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return;
  }

  const request =
    payload.exemption_request &&
    typeof payload.exemption_request === 'object' &&
    !Array.isArray(payload.exemption_request)
      ? payload.exemption_request
      : {};
  const requestData =
    request.exemption_request_data &&
    typeof request.exemption_request_data === 'object' &&
    !Array.isArray(request.exemption_request_data)
      ? request.exemption_request_data
      : {};
  const safeInteger = (value) => {
    const normalized = Number(value);
    return Number.isSafeInteger(normalized) && normalized > 0
      ? normalized
      : null;
  };
  const safeIdentifier = (value, maximumLength) =>
    typeof value === 'string' &&
    value.length <= maximumLength &&
    /^[A-Za-z0-9_-]+$/.test(value)
      ? value
      : null;
  const alertNumbers = Array.isArray(requestData.data)
    ? requestData.data.slice(0, MAX_ALERTS_PER_REQUEST).map((item) => {
        return safeInteger(
          item && typeof item === 'object' ? item.alert_number : null
        );
      })
    : [];
  const knownRequestTypes = new Set(
    Object.values(WEBHOOK_EVENT_METADATA).map(
      ({ requestDataType }) => requestDataType
    )
  );

  payload.exemption_request = {
    id: safeInteger(request.id),
    number: safeInteger(request.number),
    repository_id: safeInteger(request.repository_id),
    request_type: safeIdentifier(request.request_type, 100),
    status: safeIdentifier(request.status, 50),
    requester_comment: '[REDACTED]',
    exemption_request_data: {
      type: knownRequestTypes.has(requestData.type)
        ? requestData.type
        : null,
      alert_numbers: alertNumbers,
    },
  };
}

function sanitizeWebhookError(error) {
  const message = redactSensitiveText(
    error?.message || 'Webhook processing failed.'
  )
    .replace(/\s+/g, ' ')
    .slice(0, 500);
  const sanitized = new Error(message || 'Webhook processing failed.');
  if (
    Number.isInteger(error?.status) &&
    error.status >= 400 &&
    error.status <= 599
  ) {
    sanitized.status = error.status;
  }
  return sanitized;
}

async function mapWithConcurrency(items, limit, mapper) {
  const results = new Array(items.length);
  let nextIndex = 0;

  async function worker() {
    while (nextIndex < items.length) {
      const index = nextIndex;
      nextIndex += 1;
      results[index] = await mapper(items[index], index);
    }
  }

  await Promise.all(
    Array.from(
      { length: Math.min(limit, items.length) },
      () => worker()
    )
  );
  return results;
}

function createWebhookReviewHandler(options) {
  const {
    app,
    config = loadConfig(),
    now = Date.now,
  } = options;
  const settings = getAgenticSettings(config);
  const enabledAlertTypes = getEnabledAlertTypes(config);
  const deterministicRules = getDeterministicRules(config);
  const cacheSettings = getCacheSettings(config);
  const appIdentityCache = new BoundedTtlCache({
    ttlMs: cacheSettings.appIdentityTtlSeconds * 1000,
    maxEntries: 1,
    now,
  });
  const enterpriseInstallationCache = new BoundedTtlCache({
    ttlMs: cacheSettings.enterpriseInstallationTtlSeconds * 1000,
    maxEntries: 1,
    now,
  });
  const teamCache =
    options.teamCache ||
    new BoundedTtlCache({
      ttlMs: cacheSettings.teamMembersTtlSeconds * 1000,
      maxEntries: 100,
      now,
    });
  const controlInstallationCache =
    options.controlInstallationCache ||
    new BoundedTtlCache({
      ttlMs: cacheSettings.controlInstallationTtlSeconds * 1000,
      maxEntries: 20,
      now,
    });
  const deliveryCache =
    options.deliveryCache ||
    new BoundedTtlCache({
      ttlMs: cacheSettings.deliveryDedupeTtlSeconds * 1000,
      maxEntries: cacheSettings.deliveryDedupeMaxEntries,
      now,
    });

  async function getEnterpriseOctokit() {
    const installationId = await enterpriseInstallationCache.getOrLoad(
      settings.enterprise.toLowerCase(),
      async () => {
        const appOctokit = await app.auth();
        const { data } = await appOctokit.request(
          'GET /enterprises/{enterprise}/installation',
          {
            enterprise: settings.enterprise,
            headers: { 'X-GitHub-Api-Version': API_VERSION },
          }
        );
        return requirePositiveInteger(data?.id, 'enterprise installation ID');
      }
    );
    return app.auth(installationId);
  }

  async function getTeamLogins() {
    const cacheKey =
      `${settings.enterprise}/${settings.teamSlug}`.toLowerCase();
    return teamCache.getOrLoad(cacheKey, async () => {
      const enterpriseOctokit = await getEnterpriseOctokit();
      const members = await listEnterpriseTeamMembers(
        enterpriseOctokit,
        settings.enterprise,
        settings.teamSlug
      );
      const logins = normalizeTeamLogins(
        members.map((member) => member?.login)
      );
      if (logins.length === 0) {
        throw new Error(
          `The ${settings.enterprise}/${settings.teamSlug} enterprise team has no members.`
        );
      }
      return logins;
    });
  }

  async function getControlOctokit() {
    const workflowRepository = settings.workflowRepository;
    const cacheKey = workflowRepository.toLowerCase();
    const controlInstallationId =
      await controlInstallationCache.getOrLoad(cacheKey, async () => {
        const { owner, repo } = splitRepository(workflowRepository);
        const appOctokit = await app.auth();
        const response = await appOctokit.request(
          'GET /repos/{owner}/{repo}/installation',
          {
            owner,
            repo,
            headers: { 'X-GitHub-Api-Version': API_VERSION },
          }
        );
        return requirePositiveInteger(
          response.data?.id,
          'control repository installation ID'
        );
      });
    return app.auth(controlInstallationId);
  }

  return async function handleWebhook(context, eventName = context.name) {
    const eventMetadata = WEBHOOK_EVENT_METADATA[eventName];
    if (!eventMetadata) {
      throw new Error(`Unsupported webhook event "${eventName}".`);
    }

    if (!enabledAlertTypes.has(eventMetadata.alertType)) {
      context.log.info(
        {
          webhook_event: eventName,
          delivery_id: context.id || null,
          alert_type: eventMetadata.alertType,
        },
        'Ignoring disabled alert dismissal webhook.'
      );
      return {
        ignored: true,
        alertType: eventMetadata.alertType,
        reason: 'disabled',
      };
    }

    const event = validateWebhookContext(context, eventName);
    // GitHub restricts enterprise-owned App installations to that enterprise.
    await appIdentityCache.getOrLoad(
      settings.enterprise.toLowerCase(),
      async () => {
        const appOctokit = await app.auth();
        const { data } = await appOctokit.request('GET /app', {
          headers: { 'X-GitHub-Api-Version': API_VERSION },
        });
        validateEnterpriseApp(data, settings.enterprise);
      }
    );
    let commentValidation = { valid: true };
    if (settings.reviewMode !== 'agentic') {
      commentValidation = validateDismissalComment(
        event.dismissalRequest.requester_comment,
        deterministicRules
      );
    }

    const shouldDeny =
      settings.reviewMode !== 'agentic' && !commentValidation.valid;
    const shouldDispatch =
      settings.reviewMode === 'agentic' ||
      (settings.reviewMode === 'both' && commentValidation.valid);

    if (!shouldDeny && !shouldDispatch) {
      context.log.info(
        {
          webhook_event: eventName,
          delivery_id: event.deliveryId,
          repository: event.repository,
          dismissal_request_id: event.dismissalRequest.id,
          alert_count: event.alertNumbers.length,
        },
        'Dismissal request passed deterministic checks and remains open.'
      );
      return {
        ignored: false,
        action: 'leave_open',
        alertNumbers: event.alertNumbers,
      };
    }

    let dispatchDependenciesPromise;
    const getDispatchDependencies = () => {
      if (!dispatchDependenciesPromise) {
        dispatchDependenciesPromise = Promise.all([
          getTeamLogins(),
          getControlOctokit(),
        ]).then(([teamLogins, controlOctokit]) => ({
          teamLogins,
          controlOctokit,
        }));
      }
      return dispatchDependenciesPromise;
    };

    const results = await mapWithConcurrency(
      event.alertNumbers,
      4,
      async (alertNumber) => {
        const deliveryIdentity =
          event.deliveryId ||
          `${eventName}:${event.installationId}:${event.dismissalRequest.id}`;
        const operationKey = [
          deliveryIdentity,
          event.repository.toLowerCase(),
          event.alertType,
          alertNumber,
        ].join(':');

        return deliveryCache.runOnce(operationKey, async () => {
          if (shouldDeny) {
            const message = formatDenialMessage(
              {
                alertType: event.alertType,
                alertNumber,
                requester: event.dismissalRequest.requester_login,
                denialReason: commentValidation.reason,
                repoFullName: event.repository,
                helpContact: settings.helpContact,
              },
              config
            );
            const { owner, repo } = splitRepository(event.repository);
            try {
              await denyDismissalRequest(
                context.octokit,
                owner,
                repo,
                event.alertType,
                alertNumber,
                message
              );
              return { action: 'denied', alertNumber };
            } catch (error) {
              if (!isStaleDismissalReviewError(error)) throw error;
              return { action: 'stale_noop', alertNumber };
            }
          }

          const { teamLogins, controlOctokit } =
            await getDispatchDependencies();
          const payload = buildDispatchPayload({
            organization: event.organization,
            enterprise: settings.enterprise,
            sourceRepository: settings.workflowRepository,
            repository: event.repository,
            repositoryId: event.repositoryId,
            alertType: event.alertType,
            alertNumber,
            dismissalRequest: event.dismissalRequest,
            teamLogins,
            teamSlug: settings.teamSlug,
            model: settings.model,
            webhookEvent: eventName,
            deliveryId: event.deliveryId,
            installationId: event.installationId,
          });
          await dispatchAgenticReview(
            controlOctokit,
            settings.workflowRepository,
            payload
          );
          return { action: 'dispatched', alertNumber };
        });
      }
    );

    const duplicateCount = results.filter((result) => result.duplicate).length;
    context.log.info(
      {
        webhook_event: eventName,
        delivery_id: event.deliveryId,
        repository: event.repository,
        dismissal_request_id: event.dismissalRequest.id,
        alert_type: event.alertType,
        alert_count: event.alertNumbers.length,
        duplicate_count: duplicateCount,
        outcome: shouldDeny ? 'denied' : 'dispatched',
      },
      'Processed alert dismissal webhook.'
    );

    return {
      ignored: false,
      action: shouldDeny ? 'denied' : 'dispatched',
      alertNumbers: event.alertNumbers,
      duplicateCount,
      results,
    };
  };
}

function registerWebhookHandlers(app, options = {}) {
  const handler = createWebhookReviewHandler({ app, ...options });
  app.onAny(async (context) => {
    const eventName = context.name;
    if (
      !Object.hasOwn(WEBHOOK_EVENT_METADATA, eventName) ||
      context.payload?.action !== 'created'
    ) {
      return undefined;
    }
    try {
      return await handler(context, eventName);
    } catch (error) {
      redactWebhookPayloadForLogging(context.payload);
      throw sanitizeWebhookError(error);
    }
  });
  return handler;
}

module.exports = {
  BoundedTtlCache,
  DEFAULT_CACHE_SETTINGS,
  MAX_ALERTS_PER_REQUEST,
  WEBHOOK_EVENT_METADATA,
  WEBHOOK_EVENTS,
  createWebhookReviewHandler,
  getCacheSettings,
  getEnabledAlertTypes,
  redactWebhookPayloadForLogging,
  registerWebhookHandlers,
  sanitizeWebhookError,
  validateWebhookContext,
};
