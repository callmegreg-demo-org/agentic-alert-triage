'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  formatDenialMessage,
  getDeterministicRules,
  validateDismissalComment,
} = require('./deterministic-review');

describe('deterministic dismissal review', () => {
  const phraseRules = {
    requiredPhrase: 'mitigating control',
    requiredPattern: null,
    minimumLength: null,
    caseSensitive: false,
  };

  it('normalizes configured validation rules', () => {
    assert.deepEqual(
      getDeterministicRules({
        required_phrase: 'approved exception',
        required_pattern: '^SEC-\\d+',
        minimum_length: 20,
        case_sensitive: true,
      }),
      {
        requiredPhrase: 'approved exception',
        requiredPattern: '^SEC-\\d+',
        minimumLength: 20,
        caseSensitive: true,
      }
    );
  });

  it('accepts a comment containing the required phrase', () => {
    const result = validateDismissalComment(
      'We have a mitigating control in place via WAF rules.',
      phraseRules
    );
    assert.equal(result.valid, true);
    assert.equal(result.reason, undefined);
  });

  it('accepts the required phrase regardless of case', () => {
    assert.equal(
      validateDismissalComment(
        'MITIGATING CONTROL documented.',
        phraseRules
      ).valid,
      true
    );
  });

  it('rejects missing and empty comments when criteria are configured', () => {
    assert.match(
      validateDismissalComment('This is not relevant.', phraseRules).reason,
      /required phrase/
    );
    for (const comment of [null, undefined, '', '   ']) {
      assert.equal(
        validateDismissalComment(comment, phraseRules).valid,
        false
      );
    }
  });

  it('enforces minimum length and regular expression rules', () => {
    const rules = {
      requiredPhrase: null,
      requiredPattern: '^SEC-\\d+:',
      minimumLength: 12,
      caseSensitive: true,
    };

    assert.equal(
      validateDismissalComment('SEC-42: accepted risk', rules).valid,
      true
    );
    assert.match(
      validateDismissalComment('SEC-42:', rules).reason,
      /at least 12 characters/
    );
    assert.match(
      validateDismissalComment('sec-42: accepted risk', rules).reason,
      /required pattern/
    );
  });

  it('reports invalid configured regular expressions', () => {
    const result = validateDismissalComment('anything', {
      requiredPhrase: null,
      requiredPattern: '[',
      minimumLength: null,
      caseSensitive: false,
    });

    assert.equal(result.valid, false);
    assert.match(result.reason, /not a valid regular expression/);
  });

  it('substitutes denial message placeholders', () => {
    const message = formatDenialMessage(
      {
        alertType: 'code_scanning',
        alertNumber: 42,
        requester: 'octocat',
        denialReason: 'Missing required phrase.',
        repoFullName: 'my-org/my-repo',
        helpContact: 'enterprise security',
      },
      {
        required_phrase: 'mitigating control',
        denial_message:
          '{alert_type} #{alert_number} {requester} {required_phrase} {denial_reason} {repo_full_name} {help_contact}',
      }
    );

    assert.equal(
      message,
      'code scanning #42 octocat mitigating control Missing required phrase. my-org/my-repo enterprise security'
    );
  });

  it('uses the built-in denial template when none is configured', () => {
    const message = formatDenialMessage(
      {
        alertType: 'dependabot',
        alertNumber: 7,
        requester: undefined,
        denialReason: 'Too short.',
        repoFullName: 'org/repo',
        helpContact: 'Enterprise security desk',
      },
      {}
    );

    assert.equal(
      message,
      `DISMISSAL REQUEST DENIED.

Reason: Too short.

Next step: Create a supporting issue, then add its URL to a new dismissal request: https://github.com/org/repo/issues/new

For more help, mention the Enterprise security desk`
    );
    assert.doesNotMatch(message, /[*@]/);
  });
});
