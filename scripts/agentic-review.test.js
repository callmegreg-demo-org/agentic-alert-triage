'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const yaml = require('js-yaml');
const {
  assignAlertToTeam,
  buildDispatchPayload,
  buildReviewContext,
  DEFAULT_MODEL,
  extractIssueReferences,
  formatAgenticDenialMessage,
  getAgenticSettings,
  getAlert,
  isStaleDismissalReviewError,
  listEnterpriseTeamMembers,
  mergeAssignees,
  sanitizeAlert,
  sanitizeAgentReason,
  selectSecretScanningAssignee,
  validateDispatchEvent,
  validateEnterpriseApp,
} = require('./agentic-review');
const { main: exportWorkflowConfig, resolveWorkflowTarget } = require('./export-workflow-config');

const WORKFLOW_REPOSITORY = 'CallMeGreg/agentic-alert-triage';

function agenticConfig(overrides = {}) {
  return {
    review_mode: 'agentic',
    enterprise: 'octo-enterprise',
    alert_types: ['code_scanning', 'secret_scanning', 'dependabot'],
    agentic: {
      workflow_repository: WORKFLOW_REPOSITORY,
      ...overrides,
    },
  };
}

function createDispatchEvent(overrides = {}) {
  return {
    action: 'alert-dismissal-requested',
    repository: { full_name: WORKFLOW_REPOSITORY },
    sender: { login: 'alert-dismissal-bot[bot]' },
    client_payload: {
      schema_version: 1,
      target: {
        organization: 'octo-org',
        repository: 'octo-org/service',
        repository_id: 101,
        alert_type: 'code_scanning',
        alert_number: 8,
        dismissal_request_id: 20,
        dismissal_request_number: 2,
      },
      request: {
        id: 20,
        number: 2,
        repository_id: 101,
        status: 'open',
        request_type: 'dismiss',
        exemption_request_data_type: 'code_scanning_alert_dismissal',
        requester: { actor_name: 'octocat' },
        requester_comment: 'The finding is limited to test code.',
        dismissal_reasons: ['tests'],
      },
      review: {
        appsec_team_slug: 'ent:appsec-team',
        appsec_team_members: ['security-one', 'security-two'],
        model: 'auto',
      },
      source: {
        enterprise: 'octo-enterprise',
        repository: WORKFLOW_REPOSITORY,
        webhook_event: 'dismissal_request_code_scanning',
        delivery_id: 'delivery-123',
        installation_id: 44,
      },
      dry_run: false,
      ...overrides,
    },
  };
}

function validationEnv() {
  return {
    EXPECTED_DISPATCH_SENDER: 'alert-dismissal-bot[bot]',
    GITHUB_REPOSITORY: WORKFLOW_REPOSITORY,
  };
}

function enterpriseConfig() {
  return agenticConfig();
}

function enterpriseDispatchEvent(organization = 'octo-org') {
  const event = createDispatchEvent();
  event.client_payload.target.organization = organization;
  event.client_payload.target.repository = `${organization}/service`;
  event.client_payload.source.enterprise = 'octo-enterprise';
  return event;
}

describe('agentic configuration', () => {
  it('defaults to both review modes and the automatic model', () => {
    const settings = getAgenticSettings({
      enterprise: 'octo-enterprise',
      agentic: { workflow_repository: WORKFLOW_REPOSITORY },
    });

    assert.equal(settings.reviewMode, 'both');
    assert.equal(settings.teamSlug, 'ent:appsec-team');
    assert.equal(settings.workflowRepository, WORKFLOW_REPOSITORY);
    assert.equal(settings.model, DEFAULT_MODEL);
    assert.equal(settings.staged, true);
    assert.equal(
      settings.helpContact,
      'Enterprise AppSec team in your alert (@/ent:appsec-team)'
    );
  });

  it('requires the central workflow repository', () => {
    assert.throws(
      () => getAgenticSettings({ enterprise: 'octo-enterprise' }),
      /agentic\.workflow_repository is required/
    );
  });

  it('requires an enterprise slug for every review mode', () => {
    for (const reviewMode of ['deterministic', 'agentic', 'both']) {
      assert.throws(
        () => getAgenticSettings({ review_mode: reviewMode }, validationEnv()),
        /Invalid GitHub enterprise slug/
      );
    }
  });

  it('supports enterprise scope without inferring the control repository owner', () => {
    const settings = getAgenticSettings(enterpriseConfig(), validationEnv());
    assert.equal(settings.enterprise, 'octo-enterprise');
    assert.equal(Object.hasOwn(settings, 'organization'), false);
    assert.throws(
      () => getAgenticSettings({ review_mode: 'agentic' }, validationEnv()),
      /Invalid GitHub enterprise slug/
    );
  });

  it('rejects legacy organization configuration and malformed enterprise slugs', () => {
    for (const organization of ['octo-org', null, '']) {
      for (const reviewMode of ['deterministic', 'agentic', 'both']) {
        assert.throws(
          () => getAgenticSettings({
            ...agenticConfig(), review_mode: reviewMode, organization,
          }),
          /organization is no longer supported/
        );
      }
    }
    for (const enterprise of ['', null, 42, [], {}, '../acme', 'acme\nowner=attacker']) {
      assert.throws(
        () => getAgenticSettings({ ...enterpriseConfig(), enterprise }),
        /Invalid GitHub enterprise slug/
      );
    }
  });

  it('requires the App to be owned by the configured enterprise, not a same-named org', () => {
    validateEnterpriseApp({ owner: { slug: 'OCTO-ENTERPRISE' } }, 'octo-enterprise');
    validateEnterpriseApp(
      { owner: { login: 'OCTO-ENTERPRISE', type: 'enterprise' } },
      'octo-enterprise'
    );
    validateEnterpriseApp(
      { owner: { login: 'octo-enterprise', type: 'Enterprise' } },
      'octo-enterprise'
    );
    for (const owner of [
      null,
      { slug: 'other-enterprise' },
      { login: 'octo-enterprise', type: 'Organization' },
      { login: 'octo-enterprise' },
      { login: 'other-enterprise', type: 'enterprise' },
      { login: 'octo-enterprise', slug: 'octo-enterprise' },
      {
        login: 'octo-enterprise',
        slug: 'other-enterprise',
        type: 'enterprise',
      },
    ]) {
      assert.throws(
        () => validateEnterpriseApp({ owner }, 'octo-enterprise'),
        /requires a GitHub App owned by enterprise/
      );
    }
  });

  it('allows the control repository to use a different owner', () => {
    const settings = getAgenticSettings(
      {
        review_mode: 'agentic',
        enterprise: 'octo-enterprise',
        agentic: { workflow_repository: 'control-owner/automation' },
      },
      {}
    );

    assert.equal(settings.workflowRepository, 'control-owner/automation');
  });

  it('accepts a configured model and rejects invalid values', () => {
    assert.equal(
      getAgenticSettings(agenticConfig({ model: 'gpt-5.4' })).model,
      'gpt-5.4'
    );
    for (const model of ['', null, 42, 'model name', 'model\nname']) {
      assert.throws(
        () => getAgenticSettings(agenticConfig({ model })),
        /Invalid agentic\.model/
      );
    }
  });

  it('rejects unknown review modes and invalid trusted identifiers', () => {
    assert.throws(
      () => getAgenticSettings({ review_mode: 'automatic' }, {}),
      /Invalid review_mode/
    );
    assert.throws(
      () =>
        getAgenticSettings(
          {
            review_mode: 'agentic',
            enterprise: 'octo-enterprise\nowner=attacker',
          },
          {}
        ),
      /Invalid GitHub enterprise slug/
    );
    assert.throws(
      () =>
        getAgenticSettings(
          {
            enterprise: 'octo-enterprise',
            agentic: { appsec_team_slug: '../appsec' },
          },
          {}
        ),
      /Invalid AppSec enterprise team slug/
    );
  });

  it('only accepts enterprise team slugs, including the ent: prefix', () => {
    for (const teamSlug of ['appsec-team', '', null, 'ent:', 'ent:../appsec', 'org/team']) {
      assert.throws(
        () => getAgenticSettings(agenticConfig({ appsec_team_slug: teamSlug })),
        /Expected ent:team-name/
      );
    }
    assert.equal(
      getAgenticSettings(agenticConfig({ appsec_team_slug: 'ent:security' })).teamSlug,
      'ent:security'
    );
  });
});

describe('dispatch payloads', () => {
  it('validates multiple target organizations with one enterprise team help contact', () => {
    for (const organization of ['octo-org', 'second-org']) {
      const target = validateDispatchEvent(
        enterpriseDispatchEvent(organization),
        enterpriseConfig(),
        { ...validationEnv(), EXPECTED_INSTALLATION_ID: '44' }
      );
      assert.equal(target.organization, organization);
      assert.equal(target.owner, organization);
      assert.equal(
        target.helpContact,
        'Enterprise AppSec team in your alert (@/ent:appsec-team)'
      );
      const message = formatAgenticDenialMessage({
        config: enterpriseConfig(),
        target,
        dismissalRequest: target.dismissalRequest,
        reason:
          'The request lacks a substantive justification: the linked issue does not explain why dismissal is appropriate, provides no concrete supporting evidence, and the comment does not address the alert beyond stating a preference.',
      });
      assert.equal(
        message,
        `DISMISSAL REQUEST DENIED.

Reason: The request lacks a substantive justification: the linked issue does not explain why dismissal is appropriate, provides no concrete supporting evidence, and the comment does not address the alert beyond stating a preference.

Next step: Submit a new request with a specific explanation of why the alert can be dismissed, supporting evidence or links, and any relevant mitigating controls or remediation plan.

For more help, mention the Enterprise AppSec team in your alert (@/ent:appsec-team)`
      );
      assert.match(message, /@\/ent:appsec-team/);
      assert.doesNotMatch(message, /@\u200b\/ent:appsec-team/);
    }
  });

  it('preserves an explicit shared help contact in enterprise mode', () => {
    const config = enterpriseConfig();
    config.agentic.help_contact = 'Contact the enterprise security desk.';
    const target = validateDispatchEvent(enterpriseDispatchEvent(), config, validationEnv());
    assert.equal(target.helpContact, config.agentic.help_contact);
  });

  it('preserves a configured agentic denial template', () => {
    const config = agenticConfig({
      denial_message:
        'Custom denial for {requester}: {denial_reason} Help: {help_contact}',
    });
    const target = validateDispatchEvent(
      enterpriseDispatchEvent(),
      config,
      validationEnv()
    );

    assert.equal(
      formatAgenticDenialMessage({
        config,
        target,
        dismissalRequest: target.dismissalRequest,
        reason: 'Provide supporting evidence.',
      }),
      'Custom denial for octocat: Provide supporting evidence. Help: Enterprise AppSec team in your alert (@/ent:appsec-team)'
    );
  });

  it('rejects missing or mismatched enterprise provenance and cross-org repositories', () => {
    for (const enterprise of [undefined, '', 'other-enterprise', {}, 1]) {
      const event = enterpriseDispatchEvent();
      event.client_payload.source.enterprise = enterprise;
      assert.throws(
        () => validateDispatchEvent(event, enterpriseConfig(), validationEnv()),
        /source enterprise does not match/
      );
    }
    const event = enterpriseDispatchEvent();
    event.client_payload.target.repository = 'second-org/service';
    assert.throws(
      () => validateDispatchEvent(event, enterpriseConfig(), validationEnv()),
      /outside target organization/
    );
  });

  it('requires the App sender and rejects a token from another installation', () => {
    assert.throws(
      () => validateDispatchEvent(enterpriseDispatchEvent(), enterpriseConfig(), {}),
      /EXPECTED_DISPATCH_SENDER is required/
    );
    for (const installationId of ['45', '9001', 'invalid']) {
      assert.throws(
        () => validateDispatchEvent(enterpriseDispatchEvent(), enterpriseConfig(), {
          ...validationEnv(),
          EXPECTED_INSTALLATION_ID: installationId,
        }),
        /installation/
      );
    }
  });

  it('contains a sanitized request, source provenance, and team snapshot', () => {
    const payload = buildDispatchPayload({
      organization: 'octo-org',
      enterprise: 'octo-enterprise',
      teamSlug: 'ent:appsec-team',
      sourceRepository: WORKFLOW_REPOSITORY,
      repository: 'octo-org/service',
      repositoryId: 101,
      alertType: 'code_scanning',
      alertNumber: 12,
      dismissalRequest: {
        id: 99,
        number: 4,
        repository_id: 101,
        requester_id: 55,
        requester_login: 'octocat',
        request_type: 'dismiss',
        status: 'open',
        requester_comment:
          'Rotated github_pat_12345678901234567890 and documented the result.',
        exemption_request_data: {
          type: 'code_scanning_alert_dismissal',
          data: [{ alert_number: 12, reason: 'revoked', secret: 'omit-me' }],
        },
        metadata: { untrusted: 'omit-me-too' },
        responses: [{ body: 'opaque' }],
      },
      teamLogins: ['security-two', 'security-one'],
      model: 'auto',
      webhookEvent: 'dismissal_request_code_scanning',
      deliveryId: 'delivery-123',
      installationId: 44,
    });

    assert.equal(payload.schema_version, 1);
    assert.equal(payload.target.repository, 'octo-org/service');
    assert.equal(payload.target.repository_id, 101);
    assert.equal(payload.target.alert_number, 12);
    assert.equal(payload.request.id, 99);
    assert.equal(
      payload.request.exemption_request_data_type,
      'code_scanning_alert_dismissal'
    );
    assert.deepEqual(payload.request.dismissal_reasons, ['revoked']);
    assert.deepEqual(payload.review.appsec_team_members, [
      'security-one',
      'security-two',
    ]);
    assert.equal(payload.review.appsec_team_slug, 'ent:appsec-team');
    assert.equal(payload.review.model, 'auto');
    assert.deepEqual(payload.source, {
      enterprise: 'octo-enterprise',
      repository: WORKFLOW_REPOSITORY,
      webhook_event: 'dismissal_request_code_scanning',
      installation_id: 44,
      delivery_id: 'delivery-123',
    });
    const serialized = JSON.stringify(payload);
    assert.doesNotMatch(serialized, /github_pat_/);
    assert.doesNotMatch(serialized, /omit-me/);
    assert.doesNotMatch(serialized, /responses/);
    assert.ok(serialized.length <= 60000);
  });

  it('rejects inconsistent event, request type, and repository identity', () => {
    const base = {
      organization: 'octo-org',
      enterprise: 'octo-enterprise',
      teamSlug: 'ent:appsec-team',
      sourceRepository: WORKFLOW_REPOSITORY,
      repository: 'octo-org/service',
      repositoryId: 101,
      alertType: 'code_scanning',
      alertNumber: 12,
      dismissalRequest: {
        id: 99,
        number: 4,
        repository_id: 101,
        requester_login: 'octocat',
        request_type: 'dismiss',
        status: 'open',
        exemption_request_data: {
          type: 'code_scanning_alert_dismissal',
          data: [{ alert_number: 12 }],
        },
      },
      teamLogins: ['security-one'],
      model: 'auto',
      webhookEvent: 'dismissal_request_code_scanning',
      installationId: 44,
    };

    assert.throws(
      () =>
        buildDispatchPayload({
          ...base,
          webhookEvent: 'dismissal_request_dependabot',
        }),
      /does not match alert type/
    );
    assert.throws(
      () =>
        buildDispatchPayload({
          ...base,
          dismissalRequest: {
            ...base.dismissalRequest,
            exemption_request_data: {
              type: 'dependabot_alert_dismissal',
              data: [{ alert_number: 12 }],
            },
          },
        }),
      /does not match alert type/
    );
    assert.throws(
      () =>
        buildDispatchPayload({
          ...base,
          repository: 'another-org/service',
        }),
      /outside organization/
    );
  });

  it('validates dispatch targets and source provenance', () => {
    const event = createDispatchEvent();
    const target = validateDispatchEvent(
      event,
      agenticConfig(),
      validationEnv()
    );

    assert.equal(target.repository, 'octo-org/service');
    assert.equal(target.repositoryId, 101);
    assert.equal(target.alertNumber, 8);
    assert.equal(target.dismissalRequest.requester.actor_name, 'octocat');
    assert.equal(target.webhookEvent, 'dismissal_request_code_scanning');
    assert.equal(target.deliveryId, 'delivery-123');
    assert.equal(target.sourceInstallationId, 44);
    assert.deepEqual(target.teamLogins, [
      'security-one',
      'security-two',
    ]);

    event.client_payload.target.repository = 'another-org/service';
    assert.throws(
      () =>
        validateDispatchEvent(event, agenticConfig(), validationEnv()),
      /outside target organization/
    );
  });

  it('rejects an unexpected sender, source event, or request data type', () => {
    const wrongSender = createDispatchEvent();
    wrongSender.sender.login = 'octocat';
    assert.throws(
      () =>
        validateDispatchEvent(
          wrongSender,
          agenticConfig(),
          validationEnv()
        ),
      /does not match the configured GitHub App identity/
    );

    const wrongEvent = createDispatchEvent();
    wrongEvent.client_payload.source.webhook_event =
      'dismissal_request_dependabot';
    assert.throws(
      () =>
        validateDispatchEvent(
          wrongEvent,
          agenticConfig(),
          validationEnv()
        ),
      /webhook event does not match/
    );

    const wrongType = createDispatchEvent();
    wrongType.client_payload.request.exemption_request_data_type =
      'dependabot_alert_dismissal';
    assert.throws(
      () =>
        validateDispatchEvent(
          wrongType,
          agenticConfig(),
          validationEnv()
        ),
      /snapshot type does not match/
    );
  });

  it('rejects dispatches when agentic review or the alert type is disabled', () => {
    assert.throws(
      () =>
        validateDispatchEvent(
          createDispatchEvent(),
          {
            review_mode: 'deterministic',
            enterprise: 'octo-enterprise',
            agentic: { workflow_repository: WORKFLOW_REPOSITORY },
          },
          validationEnv()
        ),
      /Agentic review is disabled/
    );
    assert.throws(
      () =>
        validateDispatchEvent(
          createDispatchEvent(),
          {
            ...agenticConfig(),
            alert_types: ['secret_scanning'],
          },
          validationEnv()
        ),
      /not enabled/
    );
  });

  it('rejects missing, organization-local, or mismatched team snapshots', () => {
    for (const teamSlug of [undefined, 'appsec-team', 'ent:another-team', {}]) {
      const event = createDispatchEvent();
      event.client_payload.review.appsec_team_slug = teamSlug;
      assert.throws(
        () => validateDispatchEvent(event, agenticConfig(), validationEnv()),
        /Dispatch AppSec enterprise team does not match/
      );
    }
    const event = createDispatchEvent();
    event.client_payload.review.appsec_team_members = [null];
    assert.throws(
      () => validateDispatchEvent(event, agenticConfig(), validationEnv()),
      /logins must be strings/
    );
  });

  it('rejects a dispatch model that does not match trusted configuration', () => {
    const event = createDispatchEvent();
    event.client_payload.review.model = 'gpt-5.4';
    assert.throws(
      () => validateDispatchEvent(event, agenticConfig(), validationEnv()),
      /model does not match/
    );
  });
});

describe('workflow target export before installation token creation', () => {
  function appClient(owner = { slug: 'octo-enterprise' }) {
    return {
      request: async (route) => {
        assert.equal(route, 'GET /app');
        return { data: { slug: 'alert-dismissal-bot', owner } };
      },
    };
  }

  it('authenticates and exports each target org, never the control owner', async (t) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'workflow-config-'));
    t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
    for (const organization of ['octo-org', 'second-org']) {
      const outputPath = path.join(directory, organization);
      await exportWorkflowConfig({
        config: enterpriseConfig(),
        event: enterpriseDispatchEvent(organization),
        appOctokit: appClient(),
        env: { ...validationEnv(), GITHUB_OUTPUT: outputPath },
      });
      assert.equal(fs.readFileSync(outputPath, 'utf8'), `organization=${organization}\n`);
    }
  });

  it('writes no token-owner output for an untrusted sender, App, or dispatch', async (t) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'workflow-config-'));
    t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
    const outputPath = path.join(directory, 'output');
    const wrongSender = enterpriseDispatchEvent();
    wrongSender.sender.login = 'octocat';
    const wrongSource = enterpriseDispatchEvent();
    wrongSource.client_payload.source.repository = 'attacker/control';
    const badOrganization = enterpriseDispatchEvent('octo-org\nowner=attacker');
    const missingEnterprise = createDispatchEvent();
    delete missingEnterprise.client_payload.source.enterprise;
    const wrongSchema = enterpriseDispatchEvent();
    wrongSchema.client_payload.schema_version = 99;
    for (const event of [wrongSender, wrongSource, badOrganization, missingEnterprise, wrongSchema]) {
      await assert.rejects(exportWorkflowConfig({
        config: enterpriseConfig(),
        event,
        appOctokit: appClient(),
        env: { ...validationEnv(), GITHUB_OUTPUT: outputPath },
      }));
      assert.equal(fs.existsSync(outputPath), false);
    }
    for (const owner of [{ slug: 'other-enterprise' }, { login: 'octo-org' }]) {
      await assert.rejects(exportWorkflowConfig({
        config: enterpriseConfig(),
        event: enterpriseDispatchEvent(),
        appOctokit: appClient(owner),
        env: { ...validationEnv(), GITHUB_OUTPUT: outputPath },
      }), /requires a GitHub App owned by enterprise/);
      assert.equal(fs.existsSync(outputPath), false);
    }
  });

  it('rejects organization-owned Apps even when the organization matches the target', async () => {
    await assert.rejects(resolveWorkflowTarget({
      config: agenticConfig(),
      event: createDispatchEvent(),
      appOctokit: appClient({ login: 'octo-org', type: 'Organization' }),
      env: validationEnv(),
    }), /requires a GitHub App owned by enterprise/);
  });

  it('surfaces App authentication failures without exporting a target', async () => {
    await assert.rejects(resolveWorkflowTarget({
      config: enterpriseConfig(),
      event: enterpriseDispatchEvent(),
      appOctokit: { request: async () => { throw new Error('App authentication failed'); } },
      env: validationEnv(),
    }), /App authentication failed/);
  });

  it('validates both workflow phases before minting organization tokens', () => {
    const source = fs.readFileSync(path.join(
      __dirname, '../.github/workflows/agentic-dismissal-review.md'
    ), 'utf8');
    const workflow = yaml.load(source.split('---')[1]);
    const phases = [
      { steps: workflow['pre-agent-steps'], tokenId: 'review-token', script: 'prepare-agentic-review' },
      {
        steps: workflow['safe-outputs'].jobs['apply-dismissal-decision'].steps,
        tokenId: 'decision-token',
        script: 'apply-agentic-decision',
      },
    ];
    for (const { steps, tokenId, script } of phases) {
      const validationIndex = steps.findIndex((step) => step.id === 'trusted-config');
      const tokenIndex = steps.findIndex((step) => step.id === tokenId);
      const consumerIndex = steps.findIndex((step) => step.run === `node scripts/${script}.js`);
      assert.ok(validationIndex >= 0 && validationIndex < tokenIndex);
      assert.ok(tokenIndex < consumerIndex);
      assert.equal(steps[validationIndex].run, 'node scripts/export-workflow-config.js');
      assert.equal(
        steps[validationIndex].env.ALERT_DISMISSAL_APP_PRIVATE_KEY,
        '${{ secrets.ALERT_DISMISSAL_APP_PRIVATE_KEY }}'
      );
      assert.equal(
        steps[tokenIndex].with.owner,
        '${{ steps.trusted-config.outputs.organization }}'
      );
      assert.equal(
        steps[consumerIndex].env.EXPECTED_INSTALLATION_ID,
        `\${{ steps.${tokenId}.outputs.installation-id }}`
      );
      assert.equal(
        steps[consumerIndex].env.EXPECTED_DISPATCH_SENDER,
        `\${{ steps.${tokenId}.outputs.app-slug }}[bot]`
      );
    }
    assert.equal(workflow.tools.github, false);
    assert.equal(workflow.tools.edit, false);
    assert.equal(workflow.engine.id, 'copilot');
    assert.equal(
      workflow.engine.model,
      '${{ github.event.client_payload.review.model }}'
    );
    assert.equal(workflow['max-turns'], 50);
    assert.equal(workflow['safe-outputs']['threat-detection'].enabled, true);
    assert.equal(workflow.concurrency['cancel-in-progress'], true);
    assert.match(workflow.concurrency.group, /client_payload.target.repository/);
  });
});

describe('alert handling', () => {
  it('always hides secret values when reading secret scanning alerts', async () => {
    const requests = [];
    const octokit = {
      request: async (endpoint, parameters) => {
        requests.push({ endpoint, parameters });
        return { data: { number: parameters.alert_number } };
      },
    };

    await getAlert(octokit, 'octo-org', 'service', 'secret_scanning', 5);
    await getAlert(octokit, 'octo-org', 'service', 'code_scanning', 6);

    assert.equal(requests[0].parameters.hide_secret, true);
    assert.equal(
      Object.hasOwn(requests[1].parameters, 'hide_secret'),
      false
    );
  });

  it('redacts secret scanning values from alert context', () => {
    const sanitized = sanitizeAlert('secret_scanning', {
      number: 5,
      state: 'open',
      secret: 'github_pat_secret-value',
      secret_type: 'github_personal_access_token',
      assigned_to: { login: 'octocat' },
    });

    assert.equal(sanitized.secret, undefined);
    assert.doesNotMatch(JSON.stringify(sanitized), /secret-value/);
    assert.equal(sanitized.assigned_to, 'octocat');
  });

  it('redacts detected and token-shaped secrets from agent evidence', () => {
    const context = buildReviewContext({
      target: {
        enterprise: 'octo-enterprise',
        organization: 'octo-org',
        repository: 'octo-org/service',
        alertType: 'secret_scanning',
        alertNumber: 8,
        dismissalRequestId: 20,
        dismissalRequestNumber: 2,
        teamSlug: 'ent:appsec-team',
        staged: true,
        dryRun: false,
        webhookEvent: 'dismissal_request_secret_scanning',
        deliveryId: 'delivery-123',
        sourceInstallationId: 44,
      },
      dismissalRequest: {
        id: 20,
        number: 2,
        repository_id: 101,
        requester_login: 'octocat',
        status: 'open',
        request_type: 'dismiss',
        requester_comment:
          'Rotated actual-secret and github_pat_12345678901234567890.',
        exemption_request_data: {
          type: 'secret_scanning_closure',
          data: [{ alert_number: 8, secret: 'must-not-pass-through' }],
        },
      },
      alert: {
        number: 8,
        state: 'open',
        secret: 'actual-secret',
      },
      evidence: [
        {
          body: 'The exposed value was actual-secret.',
          comments: [{ body: 'Do not copy ghp_12345678901234567890.' }],
        },
      ],
    });
    const serialized = JSON.stringify(context);
    assert.equal(context.target.enterprise, 'octo-enterprise');
    assert.equal(context.target.appsec_team_slug, 'ent:appsec-team');
    assert.equal(Object.hasOwn(context.target, 'staged'), false);

    assert.doesNotMatch(serialized, /actual-secret/);
    assert.doesNotMatch(serialized, /must-not-pass-through/);
    assert.doesNotMatch(serialized, /github_pat_/);
    assert.doesNotMatch(serialized, /ghp_/);
    assert.match(serialized, /\[REDACTED SECRET\]/);
    assert.deepEqual(context.source, {
      webhook_event: 'dismissal_request_secret_scanning',
      delivery_id: 'delivery-123',
      installation_id: 44,
    });
  });

  it('preserves existing assignees', () => {
    assert.deepEqual(
      mergeAssignees(['existing', 'Alice'], ['alice', 'bob']),
      ['Alice', 'bob', 'existing']
    );
  });

  it('selects a stable secret scanning assignee', () => {
    assert.equal(
      selectSecretScanningAssignee(['zoe', 'amy', 'max'], 4),
      'max'
    );
    assert.equal(
      selectSecretScanningAssignee(['max', 'zoe', 'amy'], 4),
      'max'
    );
  });

  it('assigns snapshotted team members without collaborator reads', async () => {
    const requests = [];
    const octokit = {
      request: async (endpoint, parameters) => {
        requests.push({ endpoint, parameters });
        return { data: {} };
      },
    };

    const result = await assignAlertToTeam({
      octokit,
      owner: 'octo-org',
      repo: 'service',
      enterprise: 'octo-enterprise',
      teamSlug: 'ent:appsec-team',
      alertType: 'code_scanning',
      alertNumber: 8,
      alert: { assignees: [{ login: 'existing' }] },
      teamMembers: ['security-one', 'security-two'],
    });

    assert.deepEqual(result.assigned, ['security-one', 'security-two']);
    assert.equal(requests.length, 1);
    assert.equal(
      requests[0].endpoint,
      'PATCH /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}'
    );
    assert.deepEqual(requests[0].parameters.assignees, [
      'existing',
      'security-one',
      'security-two',
    ]);
  });

  it('does not rewrite an alert already assigned to every AppSec member', async () => {
    const result = await assignAlertToTeam({
      octokit: {
        request: async () => assert.fail('No redundant assignment is expected'),
      },
      owner: 'octo-org',
      repo: 'service',
      enterprise: 'octo-enterprise',
      teamSlug: 'ent:appsec-team',
      alertType: 'dependabot',
      alertNumber: 8,
      alert: {
        assignees: [
          { login: 'security-two' },
          { login: 'Security-One' },
        ],
      },
      teamMembers: ['security-one', 'security-two'],
    });

    assert.deepEqual(result.assigned, ['security-one', 'security-two']);
  });

  it('surfaces alert assignment endpoint failures', async () => {
    await assert.rejects(
      assignAlertToTeam({
        octokit: {
          request: async () => {
            throw new Error('assignment rejected');
          },
        },
        owner: 'octo-org',
        repo: 'service',
        enterprise: 'octo-enterprise',
        teamSlug: 'ent:appsec-team',
        alertType: 'dependabot',
        alertNumber: 8,
        alert: { assignees: [] },
        teamMembers: ['security-one'],
      }),
      /assignment rejected/
    );
  });

  it('requires a team snapshot rather than looking up organization membership', async () => {
    await assert.rejects(assignAlertToTeam({
      octokit: {
        paginate: async () => assert.fail('No membership lookup is allowed during assignment'),
        request: async () => assert.fail('No assignment without a snapshot'),
      },
      enterprise: 'octo-enterprise',
      teamSlug: 'ent:appsec-team',
      owner: 'octo-org',
      repo: 'service',
      alertType: 'code_scanning',
      alertNumber: 8,
      alert: {},
    }), /enterprise team membership snapshot is required/);
  });

  it('paginates the enterprise team memberships endpoint using the bare API slug', async () => {
    const members = [{ login: 'security-one' }, { login: 'security-two' }];
    const octokit = {
      paginate: async (endpoint, parameters) => {
        assert.equal(endpoint, 'GET /enterprises/{enterprise}/teams/{enterprise-team}/memberships');
        assert.equal(parameters.enterprise, 'octo-enterprise');
        assert.equal(parameters['enterprise-team'], 'appsec-team');
        assert.equal(parameters.per_page, 100);
        assert.equal(Object.hasOwn(parameters, 'org'), false);
        assert.equal(Object.hasOwn(parameters, 'role'), false);
        return members;
      },
    };
    assert.deepEqual(
      await listEnterpriseTeamMembers(octokit, 'octo-enterprise', 'ent:appsec-team'),
      members
    );
  });
});

describe('evidence and decision sanitization', () => {
  it('extracts only unique same-organization issue references', () => {
    const references = extractIssueReferences(
      [
        'https://github.com/octo-org/service/issues/12',
        'https://github.com/OCTO-ORG/service/issues/12',
        'https://github.com/other-org/service/issues/2',
        'https://github.com/octo-org/another/issues/3',
      ].join(' '),
      'octo-org'
    );

    assert.deepEqual(
      references.map(
        (reference) => `${reference.repo}#${reference.issue_number}`
      ),
      ['service#12', 'another#3']
    );
  });

  it('neutralizes mentions and limits agent-provided reasons', () => {
    const reason = sanitizeAgentReason(
      `Missing evidence from @security-team.
<script>alert(1)</script> [click](https://example.test) ${'x'.repeat(2000)}`
    );

    assert.equal(reason.includes('@security-team'), false);
    assert.equal(reason.includes('<script>'), false);
    assert.equal(reason.includes('https://'), false);
    assert.equal(reason.includes('\n'), false);
    assert.ok(reason.length <= 1200);
  });

  it('removes angle brackets from nested agent-provided HTML', () => {
    const reason = sanitizeAgentReason(
      'Suspicious nested markup: <scr<script>alert(1)</script>ipt>.'
    );

    assert.equal(reason.includes('<script'), false);
    assert.equal(reason.includes('<'), false);
    assert.equal(reason.includes('>'), false);
  });

  it('only treats known stale optimistic-write errors as no-ops', () => {
    assert.equal(isStaleDismissalReviewError({ status: 404 }), true);
    assert.equal(
      isStaleDismissalReviewError({
        status: 422,
        response: { data: { message: 'Request already completed' } },
      }),
      true
    );
    assert.equal(
      isStaleDismissalReviewError({
        status: 422,
        response: { data: { message: 'Validation failed' } },
      }),
      false
    );
  });
});
