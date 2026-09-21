'use strict';

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const API_VERSION = '2026-03-10';
const DISPATCH_EVENT_TYPE = 'alert-dismissal-requested';
const DISPATCH_SCHEMA_VERSION = 1;
const DEFAULT_MODEL = 'auto';
const MAX_DISPATCH_PAYLOAD_LENGTH = 60000;
const MAX_DENIAL_MESSAGE_LENGTH = 2048;
const MAX_AGENT_REASON_LENGTH = 1200;
const MAX_EVIDENCE_ISSUES = 5;
const MAX_EVIDENCE_BODY_LENGTH = 6000;
const MAX_ALERT_NUMBER = 2147483647;
const MAX_DELIVERY_ID_LENGTH = 128;
const SECRET_PATTERNS = [
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
];

const ALERT_TYPE_METADATA = {
  code_scanning: {
    dismissalSegment: 'code-scanning',
    alertPath: 'code-scanning',
    webhookEvent: 'dismissal_request_code_scanning',
    requestDataType: 'code_scanning_alert_dismissal',
  },
  secret_scanning: {
    dismissalSegment: 'secret-scanning',
    alertPath: 'secret-scanning',
    webhookEvent: 'dismissal_request_secret_scanning',
    requestDataType: 'secret_scanning_closure',
  },
  dependabot: {
    dismissalSegment: 'dependabot',
    alertPath: 'dependabot',
    webhookEvent: 'dismissal_request_dependabot',
    requestDataType: 'dependabot_alert_dismissal',
  },
};

function loadConfig(configPath = process.env.CONFIG_PATH || path.join(process.cwd(), 'config.yml')) {
  if (!fs.existsSync(configPath)) {
    throw new Error(`Config file not found: ${configPath}`);
  }

  return yaml.load(fs.readFileSync(configPath, 'utf8')) || {};
}

function getEnterpriseSlug(value) {
  if (
    typeof value !== 'string' ||
    !/^[A-Za-z0-9][A-Za-z0-9-]{0,99}$/.test(value)
  ) {
    throw new Error('Invalid GitHub enterprise slug.');
  }
  return value;
}

function getEnterpriseTeamSlug(value) {
  if (
    typeof value !== 'string' ||
    !/^ent:[A-Za-z0-9][A-Za-z0-9-]{0,99}$/.test(value)
  ) {
    throw new Error(
      'Invalid AppSec enterprise team slug. Expected ent:team-name.'
    );
  }
  return value;
}

function validateEnterpriseApp(appInfo, enterprise) {
  const owner = appInfo?.owner;
  const expectedEnterprise = enterprise.toLowerCase();
  const slugMatches =
    typeof owner?.slug === 'string' &&
    owner.slug.toLowerCase() === expectedEnterprise;
  const loginMatches =
    typeof owner?.login === 'string' &&
    owner.login.toLowerCase() === expectedEnterprise;
  const ownerType =
    typeof owner?.type === 'string' ? owner.type.toLowerCase() : null;
  const legacyEnterpriseOwner =
    slugMatches &&
    owner.login == null &&
    (ownerType === null || ownerType === 'enterprise');
  const currentEnterpriseOwner =
    loginMatches &&
    ownerType === 'enterprise' &&
    (owner.slug == null || slugMatches);

  if (!legacyEnterpriseOwner && !currentEnterpriseOwner) {
    throw new Error(
      `This service requires a GitHub App owned by enterprise ${enterprise}.`
    );
  }
}

function getAgenticModel(value) {
  const model = value === undefined ? DEFAULT_MODEL : value;
  if (
    typeof model !== 'string' ||
    model.length === 0 ||
    model.length > 128 ||
    !/^[A-Za-z0-9][A-Za-z0-9._/?=&-]*$/.test(model)
  ) {
    throw new Error(`Invalid agentic.model "${model}".`);
  }
  return model;
}

function getAgenticSettings(config) {
  const reviewMode = config.review_mode || 'both';
  if (!['deterministic', 'agentic', 'both'].includes(reviewMode)) {
    throw new Error(
      `Invalid review_mode "${reviewMode}". Expected deterministic, agentic, or both.`
    );
  }

  if (Object.hasOwn(config, 'organization')) {
    throw new Error(
      'organization is no longer supported. Configure enterprise instead.'
    );
  }
  const enterprise = getEnterpriseSlug(config.enterprise);
  const agentic = config.agentic || {};
  const teamSlug = getEnterpriseTeamSlug(
    agentic.appsec_team_slug === undefined
      ? 'ent:appsec-team'
      : agentic.appsec_team_slug
  );
  const workflowRepository = agentic.workflow_repository;
  if (!workflowRepository) {
    throw new Error('agentic.workflow_repository is required.');
  }
  const model = getAgenticModel(agentic.model);

  splitRepository(workflowRepository);

  return {
    reviewMode,
    enterprise,
    teamSlug,
    workflowRepository,
    model,
    staged: agentic.staged !== false,
    helpContact:
      agentic.help_contact || `Enterprise AppSec team (${teamSlug})`,
    denialMessage: agentic.denial_message || null,
  };
}

function getAlertTypeMetadata(alertType) {
  const metadata = ALERT_TYPE_METADATA[alertType];
  if (!metadata) {
    throw new Error(
      `Unsupported alert type "${alertType}". Expected ${Object.keys(
        ALERT_TYPE_METADATA
      ).join(', ')}.`
    );
  }
  return metadata;
}

function splitRepository(repoFullName) {
  const parts = String(repoFullName || '').split('/');
  if (
    parts.length !== 2 ||
    !/^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/.test(parts[0]) ||
    !/^[A-Za-z0-9._-]{1,100}$/.test(parts[1])
  ) {
    throw new Error(`Invalid repository name "${repoFullName}". Expected owner/repo.`);
  }
  return { owner: parts[0], repo: parts[1] };
}

function normalizeTeamLogins(teamLogins) {
  if (!Array.isArray(teamLogins)) {
    throw new Error('AppSec team members must be provided as an array.');
  }

  const uniqueLogins = new Map();
  for (const login of teamLogins) {
    if (typeof login !== 'string') {
      throw new Error('AppSec team member logins must be strings.');
    }
    uniqueLogins.set(login.toLowerCase(), login);
  }
  const normalized = [...uniqueLogins.values()];
  for (const login of normalized) {
    if (!/^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/.test(login)) {
      throw new Error(`Invalid GitHub team member login "${login}".`);
    }
  }
  return normalized.sort((a, b) => a.localeCompare(b));
}

function normalizePositiveInteger(value, label, maximum = Number.MAX_SAFE_INTEGER) {
  const normalized = Number(value);
  if (
    !Number.isSafeInteger(normalized) ||
    normalized <= 0 ||
    normalized > maximum
  ) {
    throw new Error(`Invalid ${label} "${value}".`);
  }
  return normalized;
}

function normalizeDeliveryId(value) {
  if (value == null || value === '') return null;
  const deliveryId = String(value);
  if (
    deliveryId.length > MAX_DELIVERY_ID_LENGTH ||
    !/^[A-Za-z0-9._:-]+$/.test(deliveryId)
  ) {
    throw new Error('Invalid webhook delivery ID.');
  }
  return deliveryId;
}

function buildDispatchPayload({
  organization,
  enterprise,
  sourceRepository,
  repository,
  repositoryId,
  alertType,
  alertNumber,
  dismissalRequest,
  teamLogins,
  teamSlug,
  model,
  webhookEvent,
  deliveryId = null,
  installationId,
  dryRun = false,
}) {
  if (!/^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/.test(organization)) {
    throw new Error(`Invalid GitHub organization name "${organization}".`);
  }
  const targetRepository = splitRepository(repository);
  if (targetRepository.owner.toLowerCase() !== organization.toLowerCase()) {
    throw new Error(
      `Target repository ${repository} is outside organization ${organization}.`
    );
  }
  const source = splitRepository(sourceRepository);
  const metadata = getAlertTypeMetadata(alertType);
  if (webhookEvent !== metadata.webhookEvent) {
    throw new Error(
      `Webhook event "${webhookEvent}" does not match alert type "${alertType}".`
    );
  }

  const normalizedRepositoryId = normalizePositiveInteger(
    repositoryId,
    'repository ID'
  );
  const normalizedAlertNumber = normalizePositiveInteger(
    alertNumber,
    'alert number',
    MAX_ALERT_NUMBER
  );
  const normalizedInstallationId = normalizePositiveInteger(
    installationId,
    'installation ID'
  );
  const normalizedDeliveryId = normalizeDeliveryId(deliveryId);
  const normalizedTeamLogins = normalizeTeamLogins(teamLogins);
  if (normalizedTeamLogins.length === 0) {
    throw new Error('The configured AppSec team has no members.');
  }

  const request = sanitizeDismissalRequest(dismissalRequest);
  const dismissalRequestId = normalizePositiveInteger(
    request.id,
    'dismissal request ID'
  );
  const dismissalRequestNumber = normalizePositiveInteger(
    request.number,
    'dismissal request number'
  );
  if (
    request.repository_id != null &&
    normalizePositiveInteger(request.repository_id, 'request repository ID') !==
      normalizedRepositoryId
  ) {
    throw new Error('Dismissal request repository ID does not match the target.');
  }
  if (request.exemption_request_data_type !== metadata.requestDataType) {
    throw new Error(
      `Dismissal request data type "${request.exemption_request_data_type}" does not match alert type "${alertType}".`
    );
  }

  const payload = {
    schema_version: DISPATCH_SCHEMA_VERSION,
    target: {
      organization,
      repository,
      repository_id: normalizedRepositoryId,
      alert_type: alertType,
      alert_number: normalizedAlertNumber,
      dismissal_request_id: dismissalRequestId,
      dismissal_request_number: dismissalRequestNumber,
    },
    request,
    review: {
      appsec_team_slug: getEnterpriseTeamSlug(teamSlug),
      appsec_team_members: normalizedTeamLogins,
      model: getAgenticModel(model),
    },
    source: {
      repository: `${source.owner}/${source.repo}`,
      webhook_event: webhookEvent,
      installation_id: normalizedInstallationId,
      enterprise: getEnterpriseSlug(enterprise),
    },
    dry_run: dryRun,
  };
  if (normalizedDeliveryId) {
    payload.source.delivery_id = normalizedDeliveryId;
  }

  if (JSON.stringify(payload).length > MAX_DISPATCH_PAYLOAD_LENGTH) {
    throw new Error(
      `Dispatch payload exceeds the ${MAX_DISPATCH_PAYLOAD_LENGTH}-character safety limit.`
    );
  }

  return payload;
}

async function dispatchAgenticReview(octokit, workflowRepository, payload) {
  const { owner, repo } = splitRepository(workflowRepository);
  await octokit.request('POST /repos/{owner}/{repo}/dispatches', {
    owner,
    repo,
    event_type: DISPATCH_EVENT_TYPE,
    client_payload: payload,
    headers: { 'X-GitHub-Api-Version': API_VERSION },
  });
}

async function getAlert(octokit, owner, repo, alertType, alertNumber) {
  const { alertPath } = getAlertTypeMetadata(alertType);
  const response = await octokit.request(
    `GET /repos/{owner}/{repo}/${alertPath}/alerts/{alert_number}`,
    {
      owner,
      repo,
      alert_number: alertNumber,
      ...(alertType === 'secret_scanning' ? { hide_secret: true } : {}),
      headers: { 'X-GitHub-Api-Version': API_VERSION },
    }
  );
  return response.data;
}

async function listEnterpriseTeamMembers(octokit, enterprise, teamSlug) {
  const enterpriseTeam = getEnterpriseTeamSlug(teamSlug).slice('ent:'.length);
  return octokit.paginate(
    'GET /enterprises/{enterprise}/teams/{enterprise-team}/memberships',
    {
      enterprise: getEnterpriseSlug(enterprise),
      'enterprise-team': enterpriseTeam,
      per_page: 100,
      headers: { 'X-GitHub-Api-Version': API_VERSION },
    }
  );
}

function getAssignedLogins(alertType, alert) {
  getAlertTypeMetadata(alertType);

  if (alertType === 'secret_scanning') {
    return alert?.assigned_to?.login ? [alert.assigned_to.login] : [];
  }

  return Array.isArray(alert?.assignees)
    ? alert.assignees.map((assignee) => assignee.login).filter(Boolean)
    : [];
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

  const workerCount = Math.min(limit, items.length);
  await Promise.all(Array.from({ length: workerCount }, () => worker()));
  return results;
}

function selectSecretScanningAssignee(logins, alertNumber) {
  const sorted = [...new Set(logins)].sort((a, b) => a.localeCompare(b));
  if (sorted.length === 0) return null;
  return sorted[Math.abs(Number(alertNumber)) % sorted.length];
}

function mergeAssignees(existingLogins, teamLogins) {
  const uniqueLogins = new Map();
  for (const login of [...existingLogins, ...teamLogins]) {
    const normalized = login.toLowerCase();
    if (!uniqueLogins.has(normalized)) {
      uniqueLogins.set(normalized, login);
    }
  }
  return [...uniqueLogins.values()].sort((a, b) => a.localeCompare(b));
}

async function assignAlertToTeam({
  octokit,
  owner,
  repo,
  enterprise,
  teamSlug,
  alertType,
  alertNumber,
  alert,
  teamMembers,
  dryRun = false,
}) {
  if (!Array.isArray(teamMembers)) {
    throw new Error('An AppSec enterprise team membership snapshot is required.');
  }
  const teamLogins = normalizeTeamLogins(
    teamMembers.map((member) =>
      typeof member === 'string' ? member : member?.login
    )
  );
  if (teamLogins.length === 0) {
    throw new Error(
      `The ${enterprise}/${teamSlug} enterprise team has no members.`
    );
  }

  if (alertType === 'secret_scanning') {
    const assignee = selectSecretScanningAssignee(
      teamLogins,
      alertNumber
    );

    if (!dryRun && alert?.assigned_to?.login !== assignee) {
      await octokit.request(
        'PATCH /repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}',
        {
          owner,
          repo,
          alert_number: alertNumber,
          assignee,
          headers: { 'X-GitHub-Api-Version': API_VERSION },
        }
      );
    }

    return {
      assigned: [assignee],
      skipped: [],
      limitation:
        'The secret scanning API supports one alert assignee, so one AppSec team member was selected deterministically.',
    };
  }

  const existingAssignees = getAssignedLogins(alertType, alert);
  const assignees = mergeAssignees(existingAssignees, teamLogins);
  const endpoint =
    alertType === 'code_scanning'
      ? 'PATCH /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}'
      : 'PATCH /repos/{owner}/{repo}/dependabot/alerts/{alert_number}';

  const normalizedExistingAssignees = mergeAssignees(
    existingAssignees,
    []
  ).map((login) => login.toLowerCase());
  const normalizedAssignees = assignees.map((login) => login.toLowerCase());
  const assignmentChanged =
    normalizedAssignees.length !== normalizedExistingAssignees.length ||
    normalizedAssignees.some(
      (assignee, index) => assignee !== normalizedExistingAssignees[index]
    );

  if (!dryRun && assignmentChanged) {
    await octokit.request(endpoint, {
      owner,
      repo,
      alert_number: alertNumber,
      assignees,
      headers: { 'X-GitHub-Api-Version': API_VERSION },
    });
  }

  return {
    assigned: teamLogins,
    skipped: [],
    limitation: null,
  };
}

function truncate(value, maxLength) {
  const text = String(value || '');
  return text.length > maxLength
    ? `${text.slice(0, maxLength - 3)}...`
    : text;
}

function redactSensitiveText(value, sensitiveValues = []) {
  let text = String(value || '');

  for (const sensitiveValue of sensitiveValues) {
    const secret = String(sensitiveValue || '');
    if (secret.length >= 4) {
      text = text.split(secret).join('[REDACTED SECRET]');
    }
  }

  for (const pattern of SECRET_PATTERNS) {
    text = text.replace(pattern, '[REDACTED SECRET]');
  }

  return text;
}

function sanitizeDismissalRequest(request, sensitiveValues = []) {
  const requestData = Array.isArray(request.exemption_request_data?.data)
    ? request.exemption_request_data.data
    : Array.isArray(request.data)
      ? request.data
      : [];
  const reasonValues = Array.isArray(request.dismissal_reasons)
    ? request.dismissal_reasons
    : requestData.map((item) => item?.reason);
  const requesterLogin =
    request.requester_login ||
    request.requester?.actor_name ||
    request.requester?.login ||
    null;
  const requestDataType =
    request.exemption_request_data?.type ||
    request.exemption_request_data_type ||
    null;

  return {
    id: request.id,
    number: request.number,
    repository_id: request.repository_id,
    status: truncate(request.status, 50),
    request_type: truncate(request.request_type, 100),
    exemption_request_data_type: truncate(requestDataType, 100),
    requester: requesterLogin
      ? { actor_name: truncate(requesterLogin, 100) }
      : null,
    requester_comment: truncate(
      redactSensitiveText(request.requester_comment, sensitiveValues),
      10000
    ),
    dismissal_reasons: [
      ...new Set(
        reasonValues
          .filter((reason) => typeof reason === 'string' && reason)
          .map((reason) => truncate(redactSensitiveText(reason), 100))
      ),
    ].slice(0, 10),
    created_at: truncate(request.created_at, 100),
    expires_at: truncate(request.expires_at, 100),
    html_url: truncate(request.html_url, 500),
  };
}

function sanitizeCodeScanningAlert(alert) {
  return {
    number: alert.number,
    state: alert.state,
    html_url: alert.html_url,
    rule: alert.rule
      ? {
          id: alert.rule.id,
          name: alert.rule.name,
          description: alert.rule.description,
          severity: alert.rule.severity,
          security_severity_level: alert.rule.security_severity_level,
          tags: alert.rule.tags,
        }
      : null,
    tool: alert.tool
      ? {
          name: alert.tool.name,
          version: alert.tool.version,
        }
      : null,
    most_recent_instance: alert.most_recent_instance
      ? {
          ref: alert.most_recent_instance.ref,
          state: alert.most_recent_instance.state,
          environment: alert.most_recent_instance.environment,
          category: alert.most_recent_instance.category,
          classifications: alert.most_recent_instance.classifications,
          location: alert.most_recent_instance.location,
        }
      : null,
    assignees: getAssignedLogins('code_scanning', alert),
  };
}

function sanitizeSecretScanningAlert(alert) {
  return {
    number: alert.number,
    state: alert.state,
    html_url: alert.html_url,
    secret_type: alert.secret_type,
    secret_type_display_name: alert.secret_type_display_name,
    provider: alert.provider,
    provider_slug: alert.provider_slug,
    validity: alert.validity,
    publicly_leaked: alert.publicly_leaked,
    multi_repo: alert.multi_repo,
    is_base64_encoded: alert.is_base64_encoded,
    first_location_detected: alert.first_location_detected,
    has_more_locations: alert.has_more_locations,
    assigned_to: alert.assigned_to?.login || null,
  };
}

function sanitizeDependabotAlert(alert) {
  return {
    number: alert.number,
    state: alert.state,
    html_url: alert.html_url,
    dependency: alert.dependency,
    security_advisory: alert.security_advisory
      ? {
          ghsa_id: alert.security_advisory.ghsa_id,
          cve_id: alert.security_advisory.cve_id,
          summary: alert.security_advisory.summary,
          description: truncate(
            alert.security_advisory.description,
            MAX_EVIDENCE_BODY_LENGTH
          ),
          severity: alert.security_advisory.severity,
          cvss: alert.security_advisory.cvss,
          cwes: alert.security_advisory.cwes,
          identifiers: alert.security_advisory.identifiers,
          references: alert.security_advisory.references,
        }
      : null,
    security_vulnerability: alert.security_vulnerability,
    assignees: getAssignedLogins('dependabot', alert),
  };
}

function sanitizeAlert(alertType, alert) {
  if (alertType === 'code_scanning') {
    return sanitizeCodeScanningAlert(alert);
  }
  if (alertType === 'secret_scanning') {
    return sanitizeSecretScanningAlert(alert);
  }
  if (alertType === 'dependabot') {
    return sanitizeDependabotAlert(alert);
  }
  return getAlertTypeMetadata(alertType);
}

function sanitizeEvidence(evidence, sensitiveValues = []) {
  return evidence.map((item) => ({
    ...item,
    body:
      item.body == null
        ? item.body
        : truncate(
            redactSensitiveText(item.body, sensitiveValues),
            MAX_EVIDENCE_BODY_LENGTH
          ),
    comments: Array.isArray(item.comments)
      ? item.comments.map((comment) => ({
          ...comment,
          body: truncate(
            redactSensitiveText(comment.body, sensitiveValues),
            MAX_EVIDENCE_BODY_LENGTH
          ),
        }))
      : item.comments,
  }));
}

function extractIssueReferences(text, allowedOwner, max = MAX_EVIDENCE_ISSUES) {
  const references = [];
  const seen = new Set();
  const regex =
    /https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\/issues\/(\d+)/g;
  let match;

  while ((match = regex.exec(String(text || ''))) && references.length < max) {
    const owner = match[1];
    const repo = match[2];
    const issueNumber = Number(match[3]);

    if (owner.toLowerCase() !== allowedOwner.toLowerCase()) continue;

    const key = `${owner.toLowerCase()}/${repo.toLowerCase()}#${issueNumber}`;
    if (seen.has(key)) continue;
    seen.add(key);
    references.push({
      owner,
      repo,
      issue_number: issueNumber,
      url: match[0],
    });
  }

  return references;
}

async function fetchIssueEvidence(octokit, references) {
  return mapWithConcurrency(references, 3, async (reference) => {
    try {
      const [issueResponse, commentsResponse] = await Promise.all([
        octokit.request('GET /repos/{owner}/{repo}/issues/{issue_number}', {
          owner: reference.owner,
          repo: reference.repo,
          issue_number: reference.issue_number,
          headers: { 'X-GitHub-Api-Version': API_VERSION },
        }),
        octokit.request(
          'GET /repos/{owner}/{repo}/issues/{issue_number}/comments',
          {
            owner: reference.owner,
            repo: reference.repo,
            issue_number: reference.issue_number,
            per_page: 20,
            headers: { 'X-GitHub-Api-Version': API_VERSION },
          }
        ),
      ]);

      return {
        ...reference,
        title: issueResponse.data.title,
        state: issueResponse.data.state,
        author: issueResponse.data.user?.login || null,
        author_association: issueResponse.data.author_association,
        body: truncate(issueResponse.data.body, MAX_EVIDENCE_BODY_LENGTH),
        comments: commentsResponse.data.map((comment) => ({
          author: comment.user?.login || null,
          author_association: comment.author_association,
          body: truncate(comment.body, MAX_EVIDENCE_BODY_LENGTH),
          created_at: comment.created_at,
        })),
      };
    } catch (error) {
      if (error.status === 403 || error.status === 404) {
        return {
          ...reference,
          unavailable: `GitHub returned HTTP ${error.status} while fetching this evidence.`,
        };
      }
      throw error;
    }
  });
}

function readDispatchEvent(eventPath = process.env.GITHUB_EVENT_PATH) {
  if (!eventPath || !fs.existsSync(eventPath)) {
    throw new Error('GITHUB_EVENT_PATH is not available.');
  }
  return JSON.parse(fs.readFileSync(eventPath, 'utf8'));
}

function validateDispatchEvent(event, config, env = process.env) {
  const settings = getAgenticSettings(config);
  if (settings.reviewMode !== 'agentic' && settings.reviewMode !== 'both') {
    throw new Error(
      'Agentic review is disabled. Set review_mode to agentic or both.'
    );
  }
  if (event.action !== DISPATCH_EVENT_TYPE) {
    throw new Error(
      `Unexpected repository_dispatch action "${event.action}". Expected "${DISPATCH_EVENT_TYPE}".`
    );
  }

  const payload = event.client_payload || {};
  if (payload.schema_version !== DISPATCH_SCHEMA_VERSION) {
    throw new Error(
      `Unsupported dispatch schema_version "${payload.schema_version}".`
    );
  }
  if (JSON.stringify(payload).length > MAX_DISPATCH_PAYLOAD_LENGTH) {
    throw new Error(
      `Dispatch payload exceeds the ${MAX_DISPATCH_PAYLOAD_LENGTH}-character safety limit.`
    );
  }

  const dispatchedTarget = payload.target || {};
  if (
    typeof dispatchedTarget.organization !== 'string' ||
    !/^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/.test(
      dispatchedTarget.organization
    )
  ) {
    throw new Error('Dispatch payload contains an invalid organization.');
  }

  if (!env.EXPECTED_DISPATCH_SENDER) {
    throw new Error(
      'EXPECTED_DISPATCH_SENDER is required to validate the GitHub App identity.'
    );
  }
  if (
    event.sender?.login?.toLowerCase() !==
      env.EXPECTED_DISPATCH_SENDER.toLowerCase()
  ) {
    throw new Error(
      `Dispatch sender ${event.sender?.login || '(unknown)'} does not match the configured GitHub App identity.`
    );
  }

  const { owner, repo } = splitRepository(dispatchedTarget.repository);
  if (owner.toLowerCase() !== dispatchedTarget.organization.toLowerCase()) {
    throw new Error(
      `Dispatch target ${dispatchedTarget.repository} is outside target organization ${dispatchedTarget.organization}.`
    );
  }

  const alertMetadata = getAlertTypeMetadata(dispatchedTarget.alert_type);
  if (
    Array.isArray(config.alert_types) &&
    !config.alert_types.includes(dispatchedTarget.alert_type)
  ) {
    throw new Error(
      `Alert type "${dispatchedTarget.alert_type}" is not enabled in config.yml.`
    );
  }

  const repositoryId = normalizePositiveInteger(
    dispatchedTarget.repository_id,
    'repository ID'
  );
  const alertNumber = normalizePositiveInteger(
    dispatchedTarget.alert_number,
    'alert number',
    MAX_ALERT_NUMBER
  );
  const dismissalRequestId = normalizePositiveInteger(
    dispatchedTarget.dismissal_request_id,
    'dismissal request ID'
  );
  const dismissalRequestNumber = normalizePositiveInteger(
    dispatchedTarget.dismissal_request_number,
    'dismissal request number'
  );

  const dismissalRequest = sanitizeDismissalRequest(payload.request || {});
  if (
    Number(dismissalRequest.id) !== dismissalRequestId ||
    Number(dismissalRequest.number) !== dismissalRequestNumber
  ) {
    throw new Error(
      'Dispatch request snapshot does not match the target request identifiers.'
    );
  }
  if (
    normalizePositiveInteger(
      dismissalRequest.repository_id,
      'request repository ID'
    ) !== repositoryId
  ) {
    throw new Error(
      'Dispatch request snapshot does not match the target repository ID.'
    );
  }
  if (
    dismissalRequest.exemption_request_data_type !==
    alertMetadata.requestDataType
  ) {
    throw new Error(
      'Dispatch request snapshot type does not match the target alert type.'
    );
  }

  if (
    typeof payload.review?.appsec_team_slug !== 'string' ||
    payload.review.appsec_team_slug.toLowerCase() !==
      settings.teamSlug.toLowerCase()
  ) {
    throw new Error(
      'Dispatch AppSec enterprise team does not match the configured team.'
    );
  }
  const teamLogins = normalizeTeamLogins(
    payload.review?.appsec_team_members
  );
  if (teamLogins.length === 0) {
    throw new Error('Dispatch payload contains no AppSec team members.');
  }
  if (payload.review?.model !== settings.model) {
    throw new Error(
      'Dispatch agentic model does not match the configured model.'
    );
  }

  if (
    settings.workflowRepository &&
    env.GITHUB_REPOSITORY &&
    settings.workflowRepository.toLowerCase() !==
      env.GITHUB_REPOSITORY.toLowerCase()
  ) {
    throw new Error(
      `This workflow is running in ${env.GITHUB_REPOSITORY}, but agentic.workflow_repository is ${settings.workflowRepository}.`
    );
  }

  const source = payload.source || {};
  if (
    typeof source.enterprise !== 'string' ||
    source.enterprise.toLowerCase() !== settings.enterprise.toLowerCase()
  ) {
    throw new Error(
      'Dispatch source enterprise does not match configured enterprise.'
    );
  }
  if (
    typeof source.repository !== 'string' ||
    source.repository.toLowerCase() !==
      settings.workflowRepository.toLowerCase()
  ) {
    throw new Error(
      'Dispatch source repository does not match agentic.workflow_repository.'
    );
  }
  if (
    event.repository?.full_name &&
    source.repository.toLowerCase() !== event.repository.full_name.toLowerCase()
  ) {
    throw new Error(
      'Dispatch source repository does not match the receiving repository.'
    );
  }
  if (source.webhook_event !== alertMetadata.webhookEvent) {
    throw new Error(
      'Dispatch webhook event does not match the target alert type.'
    );
  }
  const sourceInstallationId = normalizePositiveInteger(
    source.installation_id,
    'source installation ID'
  );
  if (
    env.EXPECTED_INSTALLATION_ID &&
    sourceInstallationId !== normalizePositiveInteger(
      env.EXPECTED_INSTALLATION_ID,
      'workflow installation ID'
    )
  ) {
    throw new Error(
      'Workflow token installation does not match the webhook installation.'
    );
  }
  const deliveryId = normalizeDeliveryId(source.delivery_id);

  return {
    ...settings,
    organization: dispatchedTarget.organization,
    payload,
    owner,
    repo,
    repository: `${owner}/${repo}`,
    alertType: dispatchedTarget.alert_type,
    alertNumber,
    repositoryId,
    dismissalRequestId,
    dismissalRequestNumber,
    dismissalRequest,
    teamLogins,
    dryRun: payload.dry_run === true || payload.dry_run === 'true',
    webhookEvent: source.webhook_event,
    deliveryId,
    sourceInstallationId,
  };
}

function buildReviewContext({
  target,
  dismissalRequest,
  alert,
  evidence,
}) {
  const sensitiveValues =
    target.alertType === 'secret_scanning' && alert.secret
      ? [alert.secret]
      : [];

  return {
    schema_version: 1,
    target: {
      enterprise: target.enterprise,
      organization: target.organization,
      repository: target.repository,
      alert_type: target.alertType,
      alert_number: target.alertNumber,
      dismissal_request_id: target.dismissalRequestId,
      dismissal_request_number: target.dismissalRequestNumber,
      appsec_team_slug: target.teamSlug,
    },
    source: {
      webhook_event: target.webhookEvent,
      delivery_id: target.deliveryId,
      installation_id: target.sourceInstallationId,
    },
    dismissal_request: sanitizeDismissalRequest(
      dismissalRequest,
      sensitiveValues
    ),
    alert: sanitizeAlert(target.alertType, alert),
    linked_issue_evidence: sanitizeEvidence(evidence, sensitiveValues),
  };
}

function sanitizeAgentReason(reason) {
  const normalized = String(reason || '')
    .replace(/\0/g, '')
    .replace(/[<>]/g, '')
    .replace(/!?\[([^\]]*)\]\([^)]+\)/g, '$1')
    .replace(/\bhttps?:\/\/\S+/gi, '[link omitted]')
    .replace(/@/g, '@\u200b')
    .replace(/\s+/g, ' ')
    .trim();
  if (normalized.length < 10) {
    throw new Error('The agent decision reason must be at least 10 characters.');
  }
  return truncate(normalized, MAX_AGENT_REASON_LENGTH);
}

function parseAgentDecision(outputPath = process.env.GH_AW_AGENT_OUTPUT) {
  if (!outputPath || !fs.existsSync(outputPath)) {
    throw new Error('GH_AW_AGENT_OUTPUT is not available.');
  }

  const output = JSON.parse(fs.readFileSync(outputPath, 'utf8'));
  const decisions = (output.items || []).filter(
    (item) => item.type === 'apply_dismissal_decision'
  );
  if (decisions.length !== 1) {
    throw new Error(
      `Expected exactly one apply_dismissal_decision item, found ${decisions.length}.`
    );
  }

  const decision = decisions[0].decision;
  if (!['ready_for_review', 'deny'].includes(decision)) {
    throw new Error(`Unsupported agent decision "${decision}".`);
  }

  return {
    decision,
    reason: sanitizeAgentReason(decisions[0].reason),
  };
}

function formatAgenticDenialMessage({
  config,
  target,
  dismissalRequest,
  reason,
}) {
  const requester =
    dismissalRequest.requester?.actor_name || 'requester';
  const template =
    target.denialMessage ||
    `DISMISSAL REQUEST DENIED

Review: Agentic
Requester: {requester}
Status: Not ready for human review
Reason: {denial_reason}

Next step: Submit a new request with a specific explanation of why the alert can be dismissed, supporting evidence or links, and any relevant mitigating controls or remediation plan.

Help: {help_contact}`;

  return truncate(
    template
      .replace(/{requester}/g, requester)
      .replace(/{denial_reason}/g, reason)
      .replace(/{help_contact}/g, target.helpContact)
      .replace(/{alert_type}/g, target.alertType.replace(/_/g, ' '))
      .replace(/{alert_number}/g, String(target.alertNumber))
      .replace(/{repo_full_name}/g, target.repository),
    MAX_DENIAL_MESSAGE_LENGTH
  );
}

async function denyDismissalRequest(
  octokit,
  owner,
  repo,
  alertType,
  alertNumber,
  message
) {
  const { dismissalSegment } = getAlertTypeMetadata(alertType);
  await octokit.request(
    `PATCH /repos/{owner}/{repo}/dismissal-requests/${dismissalSegment}/{alert_number}`,
    {
      owner,
      repo,
      alert_number: alertNumber,
      status: 'deny',
      message: truncate(message, MAX_DENIAL_MESSAGE_LENGTH),
      headers: { 'X-GitHub-Api-Version': API_VERSION },
    }
  );
}

function isStaleDismissalReviewError(error) {
  if (error?.status === 404) return true;
  if (error?.status !== 422) return false;

  const message = JSON.stringify(
    error.response?.data || error.message || ''
  ).toLowerCase();
  return /(already|completed|cancelled|expired|approved|denied|not open|not pending|no pending)/.test(
    message
  );
}

module.exports = {
  ALERT_TYPE_METADATA,
  API_VERSION,
  DEFAULT_MODEL,
  DISPATCH_EVENT_TYPE,
  assignAlertToTeam,
  buildDispatchPayload,
  buildReviewContext,
  denyDismissalRequest,
  dispatchAgenticReview,
  extractIssueReferences,
  fetchIssueEvidence,
  formatAgenticDenialMessage,
  getAgenticSettings,
  getAlert,
  getAssignedLogins,
  listEnterpriseTeamMembers,
  loadConfig,
  mergeAssignees,
  normalizeTeamLogins,
  parseAgentDecision,
  readDispatchEvent,
  redactSensitiveText,
  sanitizeAlert,
  sanitizeEvidence,
  sanitizeAgentReason,
  selectSecretScanningAssignee,
  splitRepository,
  isStaleDismissalReviewError,
  validateDispatchEvent,
  validateEnterpriseApp,
};
