/**
 * CI/CD platform secret patterns.
 * Derived from GitLeaks (MIT) and public documentation.
 */

import type { SecretPattern } from "../../types";

export const JENKINS_API_TOKEN: SecretPattern = {
  secretType: "JENKINS_API_TOKEN",
  patterns: [/(?:JENKINS_TOKEN|JENKINS_API_TOKEN)\s*[:=]\s*["']?([a-f0-9]{32,})["']?/gi],
};

export const JENKINS_CRUMB: SecretPattern = {
  secretType: "JENKINS_CRUMB",
  patterns: [/Jenkins-Crumb:\s*([a-f0-9]{32,})/g],
};

export const CIRCLECI_TOKEN: SecretPattern = {
  secretType: "CIRCLECI_TOKEN",
  patterns: [
    /(?:CIRCLECI_TOKEN|CIRCLE_TOKEN)\s*[:=]\s*["']?([a-f0-9]{40})["']?/g,
    /circle-token\s*[:=]\s*["']?([a-f0-9]{40})["']?/g,
  ],
};

export const TRAVIS_CI_TOKEN: SecretPattern = {
  secretType: "TRAVIS_CI_TOKEN",
  patterns: [/(?:TRAVIS_TOKEN|TRAVIS_API_TOKEN)\s*[:=]\s*["']?([A-Za-z0-9_-]{20,})["']?/g],
  minEntropy: 3.5,
};

export const GITHUB_ACTIONS_SECRET: SecretPattern = {
  secretType: "GITHUB_ACTIONS_SECRET",
  patterns: [/(?:ACTIONS_SECRET|GH_ACTION_SECRET)\s*[:=]\s*["']?([A-Za-z0-9_-]{20,})["']?/g],
  minEntropy: 3.5,
};

export const BUILDKITE_TOKEN: SecretPattern = {
  secretType: "BUILDKITE_TOKEN",
  patterns: [/bkua_[A-Za-z0-9]{40}/g],
};

export const BUILDKITE_AGENT_TOKEN: SecretPattern = {
  secretType: "BUILDKITE_AGENT_TOKEN",
  patterns: [/(?:BUILDKITE_AGENT_TOKEN)\s*[:=]\s*["']?([a-f0-9]{40,})["']?/g],
};

export const DRONE_CI_TOKEN: SecretPattern = {
  secretType: "DRONE_CI_TOKEN",
  patterns: [/(?:DRONE_TOKEN|DRONE_SERVER_TOKEN)\s*[:=]\s*["']?([A-Za-z0-9]{32,})["']?/g],
  minEntropy: 3.5,
};

export const CODECOV_TOKEN: SecretPattern = {
  secretType: "CODECOV_TOKEN",
  patterns: [/(?:CODECOV_TOKEN)\s*[:=]\s*["']?([a-f0-9-]{36})["']?/g],
};

export const SONARQUBE_TOKEN: SecretPattern = {
  secretType: "SONARQUBE_TOKEN",
  patterns: [
    /squ_[A-Za-z0-9]{40}/g,
    /sqp_[A-Za-z0-9]{40}/g,
  ],
};

export const TEAMCITY_TOKEN: SecretPattern = {
  secretType: "TEAMCITY_TOKEN",
  patterns: [/(?:TEAMCITY_TOKEN|TC_TOKEN)\s*[:=]\s*["']?([A-Za-z0-9_-]{20,})["']?/g],
  minEntropy: 3.5,
};

export const CICD_PATTERNS: SecretPattern[] = [
  JENKINS_API_TOKEN,
  JENKINS_CRUMB,
  CIRCLECI_TOKEN,
  TRAVIS_CI_TOKEN,
  GITHUB_ACTIONS_SECRET,
  BUILDKITE_TOKEN,
  BUILDKITE_AGENT_TOKEN,
  DRONE_CI_TOKEN,
  CODECOV_TOKEN,
  SONARQUBE_TOKEN,
  TEAMCITY_TOKEN,
];
