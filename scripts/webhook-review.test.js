'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  MAX_ALERTS_PER_REQUEST,
  WEBHOOK_EVENTS,
  createWebhookReviewHandler,
  registerWebhookHandlers,
  validateWebhookContext,
} = require('./webhook-review');
const { validateDispatchEvent } = require('./agentic-review');

const WORKFLOW_REPOSITORY = 'CallMeGreg/agentic-alert-triage';
const EVENT_DEFINITIONS = {
  code_scanning: {
    eventName: 'dismissal_request_code_scanning',
    dataType: 'code_scanning_alert_dismissal',
  },
  dependabot: {
    eventName: 'dismissal_request_dependabot',
    dataType: 'dependabot_alert_dismissal',
  },
  secret_scanning: {
    eventName: 'dismissal_request_secret_scanning',
    dataType: 'secret_scanning_closure',
  },
};

function createConfig(overrides = {}) {
  return {
    enterprise: 'octo-enterprise',
    review_mode: 'agentic',
    alert_types: ['code_scanning', 'dependabot', 'secret_scanning'],
    agentic: {
      workflow_repository: WORKFLOW_REPOSITORY,
      appsec_team_slug: 'ent:appsec-team',
      staged: true,
    },
    cache: {
      team_members_ttl_seconds: 300,
      control_installation_ttl_seconds: 300,
      delivery_dedupe_ttl_seconds: 300,
      delivery_dedupe_max_entries: 100,
    },
    ...overrides,
  };
}

function createPayload(
  alertType = 'code_scanning',
  {
    action = 'created',
    alertNumbers = [8],
    comment = 'Tracked in https://github.com/octo-org/service/issues/12',
    requestDataType,
    requestOverrides = {},
    payloadOverrides = {},
  } = {}
) {
  const definition = EVENT_DEFINITIONS[alertType];
  return {
    action,
    repository: {
      id: 101,
      full_name: 'octo-org/service',
      owner: { login: 'octo-org' },
    },
    organization: { login: 'octo-org' },
    installation: { id: 44 },
    sender: { login: 'octocat' },
    exemption_request: {
      id: 20,
      number: 2,
      repository_id: 101,
      requester_id: 55,
      requester_login: 'octocat',
      request_type: 'dismiss',
      exemption_request_data: {
        type: requestDataType || definition.dataType,
        data: alertNumbers.map((alertNumber, index) => ({
          alert_number: alertNumber,
          reason: index === 0 ? 'used in tests' : 'accepted risk',
          ...(alertType === 'secret_scanning'
            ? { secret_type: 'github_personal_access_token' }
            : {}),
          opaque: 'do-not-forward',
        })),
      },
      resource_identifier: 'resource/8',
      status: 'open',
      requester_comment: comment,
      metadata: { opaque: 'do-not-forward' },
      expires_at: null,
      created_at: '2026-09-18T15:00:00Z',
      responses: [{ body: 'do-not-forward' }],
      html_url:
        'https://github.com/octo-org/service/security/dismissal-requests/2',
      ...requestOverrides,
    },
    ...payloadOverrides,
  };
}

function createContext({
  alertType = 'code_scanning',
  id = 'delivery-123',
  payload,
  octokit,
} = {}) {
  return {
    id,
    name: EVENT_DEFINITIONS[alertType].eventName,
    payload: payload || createPayload(alertType),
    octokit,
    log: {
      info() {},
      warn() {},
      error() {},
    },
  };
}

function createHarness({
  config = createConfig(),
  teamMembers = [{ login: 'security-two' }, { login: 'security-one' }],
  dispatchFailure,
  teamFailure,
  installationFailure,
  enterpriseInstallationFailure,
  appInfo = { slug: 'alert-dismissal-bot', owner: { slug: 'octo-enterprise' } },
  appFailure,
  now,
} = {}) {
  const calls = {
    appAuth: [],
    appRequests: [],
    incomingRequests: [],
    teamLookups: [],
    controlRequests: [],
  };
  let dispatchAttempts = 0;

  const incomingOctokit = {
    paginate: async () => assert.fail('Organization tokens must not read team membership'),
    request: async (endpoint, parameters) => {
      calls.incomingRequests.push({ endpoint, parameters });
      return { data: {} };
    },
  };
  const enterpriseOctokit = {
    paginate: async (endpoint, parameters) => {
      calls.teamLookups.push({ endpoint, parameters });
      if (teamFailure) throw teamFailure;
      return typeof teamMembers === 'function' ? teamMembers(parameters) : teamMembers;
    },
    request: async () => assert.fail('Enterprise token must not access alerts or dispatch'),
  };
  const appOctokit = {
    request: async (endpoint, parameters) => {
      calls.appRequests.push({ endpoint, parameters });
      if (endpoint === 'GET /app') {
        if (appFailure) throw appFailure;
        return { data: appInfo };
      }
      if (endpoint === 'GET /enterprises/{enterprise}/installation') {
        assert.equal(parameters.enterprise, config.enterprise);
        if (enterpriseInstallationFailure) {
          const failure = typeof enterpriseInstallationFailure === 'function'
            ? enterpriseInstallationFailure()
            : enterpriseInstallationFailure;
          if (failure) throw failure;
        }
        return { data: { id: 8001 } };
      }
      assert.equal(endpoint, 'GET /repos/{owner}/{repo}/installation');
      if (installationFailure) throw installationFailure;
      return { data: { id: 9001 } };
    },
  };
  const controlOctokit = {
    request: async (endpoint, parameters) => {
      calls.controlRequests.push({ endpoint, parameters });
      dispatchAttempts += 1;
      if (
        dispatchFailure &&
        (typeof dispatchFailure !== 'function' ||
          dispatchFailure(dispatchAttempts))
      ) {
        throw new Error('dispatch failed');
      }
      return { data: {} };
    },
  };
  const app = {
    auth: async (installationId) => {
      calls.appAuth.push(installationId ?? null);
      if (installationId == null) return appOctokit;
      if (installationId === 8001) return enterpriseOctokit;
      assert.equal(installationId, 9001);
      return controlOctokit;
    },
    onAny() {},
  };
  const handler = createWebhookReviewHandler({
    app,
    config,
    env: {},
    now,
  });

  return {
    app,
    calls,
    controlOctokit,
    handler,
    incomingOctokit,
  };
}

describe('enterprise installation routing', () => {
  function enterpriseConfig(overrides = {}) {
    return createConfig(overrides);
  }

  function organizationContext(organization, installationId, octokit, alertType = 'code_scanning') {
    const repositoryId = installationId + 100;
    return createContext({
      alertType,
      octokit,
      payload: createPayload(alertType, {
        requestOverrides: { repository_id: repositoryId },
        payloadOverrides: {
          organization: { login: organization },
          repository: { id: repositoryId, full_name: `${organization}/service` },
          installation: { id: installationId },
        },
      }),
    });
  }

  it('shares one enterprise team across orgs while isolating alert delivery caches', async () => {
    const config = enterpriseConfig();
    const harness = createHarness({
      config,
      teamMembers: ({ enterprise }) => [{ login: `${enterprise}-security` }],
    });
    for (const alertType of Object.keys(EVENT_DEFINITIONS)) {
      const contexts = [
        organizationContext('first-org', 44, harness.incomingOctokit, alertType),
        organizationContext('second-org', 45, harness.incomingOctokit, alertType),
      ];
      const results = await Promise.all(contexts.map((context) => harness.handler(context)));
      assert.deepEqual(results.map((result) => result.duplicateCount), [0, 0]);
      const retries = await Promise.all(contexts.map((context) => harness.handler(context)));
      assert.deepEqual(retries.map((result) => result.duplicateCount), [1, 1]);
    }
    assert.equal(harness.calls.controlRequests.length, 6);
    assert.equal(harness.calls.teamLookups.length, 1);
    assert.equal(
      harness.calls.appRequests.filter(({ endpoint }) => endpoint === 'GET /app').length,
      1
    );
    assert.equal(
      harness.calls.appRequests.filter(({ endpoint }) => endpoint.includes('/installation')).length,
      2
    );
    assert.equal(harness.calls.incomingRequests.length, 0);
    for (const { parameters } of harness.calls.controlRequests) {
      assert.equal(`${parameters.owner}/${parameters.repo}`, WORKFLOW_REPOSITORY);
      const payload = parameters.client_payload;
      const org = payload.target.organization;
      assert.equal(payload.source.enterprise, 'octo-enterprise');
      assert.equal(payload.review.appsec_team_slug, 'ent:appsec-team');
      assert.deepEqual(payload.review.appsec_team_members, ['octo-enterprise-security']);
      const target = validateDispatchEvent({
        action: 'alert-dismissal-requested',
        repository: { full_name: WORKFLOW_REPOSITORY },
        sender: { login: 'alert-dismissal-bot[bot]' },
        client_payload: payload,
      }, config, {
        GITHUB_REPOSITORY: WORKFLOW_REPOSITORY,
        EXPECTED_DISPATCH_SENDER: 'alert-dismissal-bot[bot]',
        EXPECTED_INSTALLATION_ID: org === 'first-org' ? '44' : '45',
      });
      assert.equal(target.organization, org);
      assert.equal(target.repositoryId, org === 'first-org' ? 144 : 145);
    }
  });

  it('rejects wrong-enterprise and organization-owned Apps before any denial or dispatch', async () => {
    for (const reviewMode of ['deterministic', 'agentic', 'both']) {
      for (const owner of [{ slug: 'other-enterprise' }, { login: 'octo-enterprise', type: 'Organization' }]) {
        const harness = createHarness({
          config: enterpriseConfig({ review_mode: reviewMode, required_phrase: 'missing phrase' }),
          appInfo: { owner },
        });
        const context = organizationContext('first-org', 44, harness.incomingOctokit);
        // A claimed enterprise cannot replace App-authenticated ownership.
        context.payload.enterprise = { slug: 'octo-enterprise' };
        await assert.rejects(harness.handler(context), /requires a GitHub App owned by enterprise/);
        assert.equal(harness.calls.incomingRequests.length, 0);
        assert.equal(harness.calls.controlRequests.length, 0);
        assert.equal(harness.calls.teamLookups.length, 0);
      }
    }
  });

  it('refreshes cached enterprise identity and retries failures', async () => {
    let now = 0;
    const appInfo = { owner: { slug: 'octo-enterprise' } };
    const harness = createHarness({
      config: enterpriseConfig({ review_mode: 'deterministic', cache: { app_identity_ttl_seconds: 1 } }),
      appInfo,
      now: () => now,
    });
    const context = organizationContext('first-org', 44, harness.incomingOctokit);
    await harness.handler(context);
    now = 1001;
    appInfo.owner.slug = 'other-enterprise';
    await assert.rejects(harness.handler(context), /requires a GitHub App owned by enterprise/);
    appInfo.owner.slug = 'octo-enterprise';
    await harness.handler(context);
    assert.equal(harness.calls.appRequests.length, 3);
  });

  it('surfaces enterprise identity API errors and does not fall back to payload data', async () => {
    const harness = createHarness({
      config: enterpriseConfig(),
      appFailure: new Error('App identity unavailable'),
    });
    await assert.rejects(
      harness.handler(organizationContext('first-org', 44, harness.incomingOctokit)),
      /App identity unavailable/
    );
    assert.equal(harness.calls.controlRequests.length, 0);
    assert.equal(harness.calls.teamLookups.length, 0);
  });

  it('keeps deterministic denials on each incoming organization installation', async () => {
    const harness = createHarness({
      config: enterpriseConfig({ review_mode: 'deterministic', required_phrase: 'missing phrase' }),
    });
    for (const [org, installationId] of [['first-org', 44], ['second-org', 45]]) {
      const octokit = {
        request: async (endpoint, parameters) => {
          assert.match(endpoint, /dismissal-requests/);
          assert.equal(parameters.owner, org);
        },
      };
      const result = await harness.handler(organizationContext(org, installationId, octokit));
      assert.equal(result.action, 'denied');
    }
    assert.equal(harness.calls.controlRequests.length, 0);
  });

  it('rejects legacy or missing enterprise scope when the service starts', () => {
    assert.throws(
      () => createHarness({ config: { ...createConfig(), organization: 'octo-org' } }),
      /organization is no longer supported/
    );
    const config = createConfig();
    delete config.enterprise;
    assert.throws(() => createHarness({ config }), /Invalid GitHub enterprise slug/);
  });

  it('surfaces enterprise installation failures and retries failed lookups', async () => {
    let attempt = 0;
    const harness = createHarness({
      enterpriseInstallationFailure: () => {
        attempt += 1;
        return attempt === 1
          ? Object.assign(new Error('enterprise installation missing'), { status: 404 })
          : null;
      },
    });
    const context = createContext({ octokit: harness.incomingOctokit });
    await assert.rejects(harness.handler(context), /enterprise installation missing/);
    assert.equal(harness.calls.teamLookups.length, 0);
    assert.equal(harness.calls.controlRequests.length, 0);
    assert.equal((await harness.handler(context)).action, 'dispatched');
    assert.equal(attempt, 2);
    assert.equal(harness.calls.teamLookups.length, 1);
  });

  it('rejects empty or malformed enterprise membership and retries failed team loads', async () => {
    for (const invalidMembers of [[], [{}], [{ login: null }]]) {
      let attempt = 0;
      const harness = createHarness({
        teamMembers: () => {
          attempt += 1;
          return attempt === 1 ? invalidMembers : [{ login: 'security-one' }];
        },
      });
      const context = createContext({ octokit: harness.incomingOctokit });
      await assert.rejects(harness.handler(context), /no members|logins must be strings/);
      assert.equal(harness.calls.controlRequests.length, 0);
      assert.equal((await harness.handler(context)).action, 'dispatched');
      assert.equal(attempt, 2);
    }
  });

  it('expires enterprise membership and installation caches independently', async () => {
    let now = 0;
    let member = 'security-one';
    const harness = createHarness({
      config: createConfig({
        cache: {
          team_members_ttl_seconds: 1,
          enterprise_installation_ttl_seconds: 2,
        },
      }),
      teamMembers: () => [{ login: member }],
      now: () => now,
    });
    for (const [id, time, login] of [
      ['first', 0, 'security-one'],
      ['second', 1001, 'security-two'],
      ['third', 2001, 'security-three'],
    ]) {
      now = time;
      member = login;
      await harness.handler(createContext({ id, octokit: harness.incomingOctokit }));
    }
    assert.equal(harness.calls.teamLookups.length, 3);
    assert.equal(harness.calls.appRequests.filter(
      ({ endpoint }) => endpoint === 'GET /enterprises/{enterprise}/installation'
    ).length, 2);
    assert.deepEqual(
      harness.calls.controlRequests.map(({ parameters }) => parameters.client_payload.review.appsec_team_members),
      [['security-one'], ['security-two'], ['security-three']]
    );
  });
});

describe('webhook registration and validation', () => {
  it('registers only the three official created webhook actions', () => {
    const registrations = [];
    const app = {
      auth: async () => {
        throw new Error('not called');
      },
      onAny: (handler) => {
        registrations.push(handler);
      },
    };

    registerWebhookHandlers(app, {
      config: createConfig({ review_mode: 'deterministic' }),
      env: {},
    });

    assert.deepEqual([...WEBHOOK_EVENTS].sort(), [
      'dismissal_request_code_scanning.created',
      'dismissal_request_dependabot.created',
      'dismissal_request_secret_scanning.created',
    ]);
    assert.equal(registrations.length, 1);
    assert.equal(typeof registrations[0], 'function');
  });

  it('routes a registered event into the webhook processor', async () => {
    let registeredHandler;
    const harness = createHarness();
    harness.app.onAny = (handler) => {
      registeredHandler = handler;
    };
    registerWebhookHandlers(harness.app, {
      config: createConfig(),
      env: {},
    });

    await registeredHandler(
      createContext({ octokit: harness.incomingOctokit })
    );

    assert.equal(harness.calls.controlRequests.length, 1);
    assert.equal(
      harness.calls.controlRequests[0].parameters.event_type,
      'alert-dismissal-requested'
    );

    await registeredHandler({
      ...createContext({ octokit: harness.incomingOctokit }),
      id: 'delivery-ignored',
      name: 'issues',
      payload: { action: 'opened' },
    });
    assert.equal(harness.calls.controlRequests.length, 1);
  });

  it('redacts requester content before Probot propagates handler errors', async () => {
    let registeredHandler;
    const harness = createHarness({
      dispatchFailure: () => true,
    });
    harness.app.onAny = (handler) => {
      registeredHandler = handler;
    };
    registerWebhookHandlers(harness.app, {
      config: createConfig(),
      env: {},
    });
    const context = createContext({
      payload: createPayload('code_scanning', {
        comment: 'Do not log github_pat_12345678901234567890.',
      }),
      octokit: harness.incomingOctokit,
    });

    await assert.rejects(registeredHandler(context), /dispatch failed/);

    const serialized = JSON.stringify(context.payload.exemption_request);
    assert.equal(
      context.payload.exemption_request.requester_comment,
      '[REDACTED]'
    );
    assert.doesNotMatch(serialized, /github_pat_/);
    assert.doesNotMatch(serialized, /opaque/);
    assert.doesNotMatch(serialized, /responses/);
  });

  it('rejects event and exemption request type mismatches', () => {
    const context = createContext({
      payload: createPayload('code_scanning', {
        requestDataType: 'dependabot_alert_dismissal',
      }),
    });

    assert.throws(
      () =>
        validateWebhookContext(
          context,
          'dismissal_request_code_scanning'
        ),
      /does not match/
    );
  });

  it('rejects non-created actions and out-of-range alert batches', () => {
    assert.throws(
      () =>
        validateWebhookContext(
          createContext({
            payload: createPayload('code_scanning', {
              action: 'response_submitted',
            }),
          }),
          'dismissal_request_code_scanning'
        ),
      /Expected "created"/
    );

    const tooMany = Array.from(
      { length: MAX_ALERTS_PER_REQUEST + 1 },
      (_, index) => index + 1
    );
    assert.throws(
      () =>
        validateWebhookContext(
          createContext({
            payload: createPayload('code_scanning', {
              alertNumbers: tooMany,
            }),
          }),
          'dismissal_request_code_scanning'
        ),
      /must contain 1-100 alerts/
    );
  });

  it('safely ignores subscribed alert types disabled in config', async () => {
    const harness = createHarness({
      config: createConfig({ alert_types: ['code_scanning'] }),
    });
    const context = createContext({
      alertType: 'dependabot',
      payload: {
        action: 'created',
        repository: { full_name: 'malformed-but-ignored' },
      },
      octokit: harness.incomingOctokit,
    });

    const result = await harness.handler(
      context,
      'dismissal_request_dependabot'
    );

    assert.equal(result.ignored, true);
    assert.equal(result.reason, 'disabled');
    assert.equal(harness.calls.teamLookups.length, 0);
    assert.equal(harness.calls.appAuth.length, 0);
  });
});

describe('agentic webhook dispatch', () => {
  it('dispatches once per unique alert number in a multi-alert request', async () => {
    const harness = createHarness();
    const context = createContext({
      payload: createPayload('code_scanning', {
        alertNumbers: [8, 8, 9, 10, 9],
      }),
      octokit: harness.incomingOctokit,
    });

    const result = await harness.handler(
      context,
      'dismissal_request_code_scanning'
    );

    assert.deepEqual(result.alertNumbers, [8, 9, 10]);
    assert.equal(harness.calls.controlRequests.length, 3);
    assert.deepEqual(
      harness.calls.controlRequests.map(
        (call) => call.parameters.client_payload.target.alert_number
      ),
      [8, 9, 10]
    );
  });

  it('builds a bounded redacted schema-v1 snapshot without refetching the request', async () => {
    const harness = createHarness();
    const context = createContext({
      payload: createPayload('secret_scanning', {
        alertNumbers: [21],
        comment:
          'Rotated github_pat_12345678901234567890; see the linked issue.',
      }),
      alertType: 'secret_scanning',
      octokit: harness.incomingOctokit,
    });

    await harness.handler(
      context,
      'dismissal_request_secret_scanning'
    );

    const dispatch =
      harness.calls.controlRequests[0].parameters.client_payload;
    const serialized = JSON.stringify(dispatch);
    assert.equal(dispatch.schema_version, 1);
    assert.equal(dispatch.target.alert_type, 'secret_scanning');
    assert.equal(dispatch.target.repository_id, 101);
    assert.equal(
      dispatch.request.exemption_request_data_type,
      'secret_scanning_closure'
    );
    assert.deepEqual(dispatch.request.dismissal_reasons, [
      'used in tests',
    ]);
    assert.deepEqual(dispatch.source, {
      enterprise: 'octo-enterprise',
      repository: WORKFLOW_REPOSITORY,
      webhook_event: 'dismissal_request_secret_scanning',
      installation_id: 44,
      delivery_id: 'delivery-123',
    });
    assert.doesNotMatch(serialized, /github_pat_/);
    assert.doesNotMatch(serialized, /opaque/);
    assert.doesNotMatch(serialized, /responses/);
    assert.ok(serialized.length <= 60000);
    assert.equal(
      harness.calls.incomingRequests.some(({ endpoint }) =>
        endpoint.includes('dismissal-requests')
      ),
      false
    );
  });

  it('caches sanitized enterprise team membership using the enterprise installation', async () => {
    const harness = createHarness();
    await harness.handler(
      createContext({
        id: 'delivery-one',
        octokit: harness.incomingOctokit,
      }),
      'dismissal_request_code_scanning'
    );
    await harness.handler(
      createContext({
        id: 'delivery-two',
        octokit: harness.incomingOctokit,
      }),
      'dismissal_request_code_scanning'
    );

    assert.equal(harness.calls.teamLookups.length, 1);
    assert.equal(
      harness.calls.teamLookups[0].endpoint,
      'GET /enterprises/{enterprise}/teams/{enterprise-team}/memberships'
    );
    assert.equal(harness.calls.teamLookups[0].parameters.enterprise, 'octo-enterprise');
    assert.equal(harness.calls.teamLookups[0].parameters['enterprise-team'], 'appsec-team');
    assert.equal(harness.calls.appAuth.filter((id) => id === 8001).length, 1);
    const payloads = harness.calls.controlRequests.map(
      (call) => call.parameters.client_payload
    );
    assert.deepEqual(payloads[0].review.appsec_team_members, [
      'security-one',
      'security-two',
    ]);
    assert.equal(payloads[0].review.model, 'auto');
    assert.deepEqual(
      payloads[1].review.appsec_team_members,
      payloads[0].review.appsec_team_members
    );
  });

  it('resolves and caches the control installation using app authentication', async () => {
    const harness = createHarness();
    await harness.handler(
      createContext({
        id: 'delivery-one',
        octokit: harness.incomingOctokit,
      }),
      'dismissal_request_code_scanning'
    );
    await harness.handler(
      createContext({
        id: 'delivery-two',
        octokit: harness.incomingOctokit,
      }),
      'dismissal_request_code_scanning'
    );

    assert.equal(harness.calls.appAuth.filter((id) => id === 9001).length, 2);
    const controlLookups = harness.calls.appRequests.filter(
      ({ endpoint }) => endpoint === 'GET /repos/{owner}/{repo}/installation'
    );
    assert.equal(controlLookups.length, 1);
    assert.equal(
      controlLookups[0].endpoint,
      'GET /repos/{owner}/{repo}/installation'
    );
    assert.equal(controlLookups[0].parameters.owner, 'CallMeGreg');
    assert.equal(
      controlLookups[0].parameters.repo,
      'agentic-alert-triage'
    );
    assert.equal(
      harness.calls.incomingRequests.some(
        ({ endpoint }) =>
          endpoint === 'POST /repos/{owner}/{repo}/dispatches'
      ),
      false
    );
  });
});

describe('review modes and retry behavior', () => {
  it('denies invalid deterministic requests with the incoming installation token', async () => {
    const harness = createHarness({
      config: createConfig({
        review_mode: 'deterministic',
        required_phrase: 'approved exception',
      }),
    });

    const result = await harness.handler(
      createContext({
        payload: createPayload('code_scanning', {
          comment: 'No supporting phrase.',
        }),
        octokit: harness.incomingOctokit,
      }),
      'dismissal_request_code_scanning'
    );

    assert.equal(result.action, 'denied');
    assert.equal(harness.calls.incomingRequests.length, 1);
    assert.equal(
      harness.calls.incomingRequests[0].endpoint,
      'PATCH /repos/{owner}/{repo}/dismissal-requests/code-scanning/{alert_number}'
    );
    assert.deepEqual(harness.calls.appAuth, [null]);
    assert.equal(harness.calls.teamLookups.length, 0);
  });

  it('leaves valid deterministic requests open after verifying enterprise App ownership', async () => {
    const harness = createHarness({
      config: createConfig({
        review_mode: 'deterministic',
        required_phrase: 'approved exception',
      }),
    });

    const result = await harness.handler(
      createContext({
        payload: createPayload('code_scanning', {
          comment: 'This has an approved exception.',
        }),
        octokit: harness.incomingOctokit,
      }),
      'dismissal_request_code_scanning'
    );

    assert.equal(result.action, 'leave_open');
    assert.equal(harness.calls.incomingRequests.length, 0);
    assert.deepEqual(harness.calls.appAuth, [null]);
  });

  it('dispatches every request in agentic mode regardless of deterministic criteria', async () => {
    const harness = createHarness({
      config: createConfig({
        review_mode: 'agentic',
        required_phrase: 'approved exception',
      }),
    });

    await harness.handler(
      createContext({
        payload: createPayload('code_scanning', {
          comment: 'Missing the configured phrase.',
        }),
        octokit: harness.incomingOctokit,
      }),
      'dismissal_request_code_scanning'
    );

    assert.equal(harness.calls.controlRequests.length, 1);
    assert.equal(harness.calls.incomingRequests.length, 0);
  });

  it('denies invalid requests and dispatches valid requests in both mode', async () => {
    const invalidHarness = createHarness({
      config: createConfig({
        review_mode: 'both',
        required_phrase: 'approved exception',
      }),
    });
    await invalidHarness.handler(
      createContext({
        payload: createPayload('dependabot', {
          comment: 'Missing the configured phrase.',
        }),
        alertType: 'dependabot',
        octokit: invalidHarness.incomingOctokit,
      }),
      'dismissal_request_dependabot'
    );
    assert.equal(invalidHarness.calls.incomingRequests.length, 1);
    assert.equal(invalidHarness.calls.controlRequests.length, 0);

    const validHarness = createHarness({
      config: createConfig({
        review_mode: 'both',
        required_phrase: 'approved exception',
      }),
    });
    await validHarness.handler(
      createContext({
        payload: createPayload('dependabot', {
          comment: 'Approved exception with linked evidence.',
        }),
        alertType: 'dependabot',
        octokit: validHarness.incomingOctokit,
      }),
      'dismissal_request_dependabot'
    );
    assert.equal(validHarness.calls.incomingRequests.length, 0);
    assert.equal(validHarness.calls.controlRequests.length, 1);
  });

  it('deduplicates repeated deliveries in memory', async () => {
    const harness = createHarness();
    const context = createContext({ octokit: harness.incomingOctokit });

    const first = await harness.handler(
      context,
      'dismissal_request_code_scanning'
    );
    const second = await harness.handler(
      context,
      'dismissal_request_code_scanning'
    );

    assert.equal(first.duplicateCount, 0);
    assert.equal(second.duplicateCount, 1);
    assert.equal(harness.calls.controlRequests.length, 1);
  });

  it('releases failed deliveries so GitHub retries can succeed', async () => {
    const harness = createHarness({
      dispatchFailure: (attempt) => attempt === 1,
    });
    const context = createContext({ octokit: harness.incomingOctokit });

    await assert.rejects(
      harness.handler(context, 'dismissal_request_code_scanning'),
      /dispatch failed/
    );
    const retry = await harness.handler(
      context,
      'dismissal_request_code_scanning'
    );

    assert.equal(retry.action, 'dispatched');
    assert.equal(retry.duplicateCount, 0);
    assert.equal(harness.calls.controlRequests.length, 2);
  });

  it('surfaces team and control installation failures', async () => {
    const teamHarness = createHarness({
      teamFailure: new Error('team lookup failed'),
    });
    await assert.rejects(
      teamHarness.handler(
        createContext({ octokit: teamHarness.incomingOctokit }),
        'dismissal_request_code_scanning'
      ),
      /team lookup failed/
    );

    const installationHarness = createHarness({
      installationFailure: new Error('control installation missing'),
    });
    await assert.rejects(
      installationHarness.handler(
        createContext({ octokit: installationHarness.incomingOctokit }),
        'dismissal_request_code_scanning'
      ),
      /control installation missing/
    );
  });

  it('treats stale deterministic denial responses as safe no-ops', async () => {
    const harness = createHarness({
      config: createConfig({
        review_mode: 'deterministic',
        required_phrase: 'approved exception',
      }),
    });
    harness.incomingOctokit.request = async (endpoint, parameters) => {
      harness.calls.incomingRequests.push({ endpoint, parameters });
      const error = new Error('Request already completed');
      error.status = 422;
      error.response = { data: { message: 'Request already completed' } };
      throw error;
    };

    const result = await harness.handler(
      createContext({
        payload: createPayload('code_scanning', {
          comment: 'Missing the configured phrase.',
        }),
        octokit: harness.incomingOctokit,
      }),
      'dismissal_request_code_scanning'
    );

    assert.equal(result.results[0].value.action, 'stale_noop');
  });
});
