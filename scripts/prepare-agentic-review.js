#!/usr/bin/env node

'use strict';

const fs = require('fs');
const path = require('path');
const { Octokit } = require('@octokit/rest');
const {
  buildReviewContext,
  extractIssueReferences,
  fetchIssueEvidence,
  getAlert,
  getAssignedLogins,
  loadConfig,
  readDispatchEvent,
  validateDispatchEvent,
} = require('./agentic-review');

async function main() {
  const config = loadConfig();
  const event = readDispatchEvent();
  const target = validateDispatchEvent(event, config);
  const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });
  const dismissalRequest = target.dismissalRequest;

  const alert = await getAlert(
    octokit,
    target.owner,
    target.repo,
    target.alertType,
    target.alertNumber
  );

  const evidenceReferences = extractIssueReferences(
    dismissalRequest.requester_comment,
    target.organization
  );
  const evidence = await fetchIssueEvidence(octokit, evidenceReferences);
  const context = buildReviewContext({
    target,
    dismissalRequest,
    alert,
    evidence,
  });

  const outputPath = path.join(
    process.cwd(),
    '.github',
    'agentic-review-context.json'
  );
  fs.writeFileSync(outputPath, `${JSON.stringify(context, null, 2)}\n`, {
    mode: 0o600,
  });

  console.log(
    `Prepared sanitized context for ${target.repository} ${target.alertType} alert #${target.alertNumber}.`
  );
  console.log(
    `Current assignees: ${getAssignedLogins(target.alertType, alert).join(', ') || '(none)'}`
  );
  console.log(`Linked evidence items fetched: ${evidence.length}`);
}

if (require.main === module) {
  main().catch((error) => {
    console.error(`[FATAL] ${error.message || error}`);
    process.exit(1);
  });
}

module.exports = { main };
