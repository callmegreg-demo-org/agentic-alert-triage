'use strict';

const { ALERT_TYPE_METADATA } = require('./agentic-review');

function getDeterministicRules(config = {}) {
  const configuredReasons = config.allowed_dismissal_reasons;
  const allowedDismissalReasons = {};
  if (configuredReasons !== undefined) {
    if (
      !configuredReasons ||
      typeof configuredReasons !== 'object' ||
      Array.isArray(configuredReasons)
    ) {
      throw new Error(
        'allowed_dismissal_reasons must be an object keyed by alert type.'
      );
    }
    for (const [alertType, reasons] of Object.entries(configuredReasons)) {
      if (!Object.hasOwn(ALERT_TYPE_METADATA, alertType)) {
        throw new Error(
          `Unsupported alert type "${alertType}" in allowed_dismissal_reasons.`
        );
      }
      if (
        !Array.isArray(reasons) ||
        reasons.length === 0 ||
        reasons.some(
          (reason) =>
            typeof reason !== 'string' ||
            !reason.trim() ||
            reason.length > 100
        )
      ) {
        throw new Error(
          `allowed_dismissal_reasons.${alertType} must be a non-empty array of non-empty reason strings of at most 100 characters.`
        );
      }
      allowedDismissalReasons[alertType] = [...new Set(reasons)];
    }
  }

  return {
    allowedDismissalReasons,
    requiredPhrase: config.required_phrase ?? null,
    requiredPattern: config.required_pattern ?? null,
    minimumLength:
      Number.isFinite(config.minimum_length) && config.minimum_length > 0
        ? config.minimum_length
        : null,
    caseSensitive: config.case_sensitive === true,
  };
}

function validateDismissalReasons(reasons, alertType, rules = {}) {
  const allowedReasons = rules.allowedDismissalReasons?.[alertType];
  if (
    allowedReasons === undefined ||
    reasons.every((reason) => allowedReasons.includes(reason))
  ) {
    return { valid: true };
  }

  return {
    valid: false,
    reason: `The dismissal reason is not permitted for ${alertType.replace(/_/g, ' ')}. Please resubmit the dismissal request using one of the permitted reasons: ${allowedReasons.join(', ')}.`,
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
  return `DISMISSAL REQUEST DENIED.

Reason: {denial_reason}

Next step: Create a supporting issue, then add its URL to a new dismissal request: https://github.com/{repo_full_name}/issues/new

For more help, mention the {help_contact}`;
}

function formatDenialMessage(
  {
    alertType,
    alertNumber,
    requester,
    denialReason,
    repoFullName,
    helpContact,
  },
  config = {}
) {
  const template =
    typeof config.denial_message === 'string' &&
    config.denial_message.trim()
      ? config.denial_message
      : getDefaultDenialTemplate();

  const message = template
    .replace(/{alert_type}/g, alertType.replace(/_/g, ' '))
    .replace(/{alert_number}/g, String(alertNumber))
    .replace(/{requester}/g, requester || 'unknown')
    .replace(/{required_phrase}/g, config.required_phrase || '')
    .replace(/{denial_reason}/g, denialReason)
    .replace(/{repo_full_name}/g, repoFullName)
    .replace(/{help_contact}/g, helpContact || '');

  return template.includes('{denial_reason}')
    ? message
    : `Reason: ${denialReason}\n\n${message}`;
}

module.exports = {
  formatDenialMessage,
  getDeterministicRules,
  validateDismissalComment,
  validateDismissalReasons,
};
