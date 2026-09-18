'use strict';

function getDeterministicRules(config = {}) {
  return {
    requiredPhrase: config.required_phrase ?? null,
    requiredPattern: config.required_pattern ?? null,
    minimumLength:
      Number.isFinite(config.minimum_length) && config.minimum_length > 0
        ? config.minimum_length
        : null,
    caseSensitive: config.case_sensitive === true,
  };
}

function validateDismissalComment(comment, rules = {}) {
  const {
    requiredPhrase = null,
    requiredPattern = null,
    minimumLength = null,
    caseSensitive = false,
  } = rules;
  const trimmed = String(comment || '').trim();

  if (minimumLength != null && trimmed.length < minimumLength) {
    return {
      valid: false,
      reason: `The dismissal comment must be at least ${minimumLength} characters long (found ${trimmed.length}).`,
    };
  }

  if (requiredPhrase) {
    const haystack = caseSensitive ? trimmed : trimmed.toLowerCase();
    const needle = caseSensitive
      ? requiredPhrase
      : requiredPhrase.toLowerCase();

    if (!haystack.includes(needle)) {
      return {
        valid: false,
        reason: `The dismissal comment did not include the required phrase: "${requiredPhrase}"`,
      };
    }
  }

  if (requiredPattern) {
    let regex;
    try {
      regex = new RegExp(requiredPattern, caseSensitive ? '' : 'i');
    } catch (error) {
      return {
        valid: false,
        reason: `The configured required_pattern is not a valid regular expression: ${error.message}`,
      };
    }

    if (!regex.test(trimmed)) {
      return {
        valid: false,
        reason: `The dismissal comment did not match the required pattern: "${requiredPattern}"`,
      };
    }
  }

  return { valid: true };
}

function getDefaultDenialTemplate() {
  return `DISMISSAL REQUEST DENIED

Review: Automated criteria
Alert: {alert_type} #{alert_number}
Requester: {requester}
Status: The dismissal comment did not meet the required criteria
Reason: {denial_reason}

Next step: Submit a new dismissal request with an updated comment that satisfies the requirements.

Source: Alert Dismissal Automation for {repo_full_name}`;
}

function formatDenialMessage(
  {
    alertType,
    alertNumber,
    requester,
    denialReason,
    repoFullName,
  },
  config = {}
) {
  const template =
    typeof config.denial_message === 'string' &&
    config.denial_message.trim()
      ? config.denial_message
      : getDefaultDenialTemplate();

  return template
    .replace(/{alert_type}/g, alertType.replace(/_/g, ' '))
    .replace(/{alert_number}/g, String(alertNumber))
    .replace(/{requester}/g, requester || 'unknown')
    .replace(/{required_phrase}/g, config.required_phrase || '')
    .replace(/{denial_reason}/g, denialReason)
    .replace(/{repo_full_name}/g, repoFullName);
}

module.exports = {
  formatDenialMessage,
  getDeterministicRules,
  validateDismissalComment,
};
