/**
 * Infrastructure and DevOps secret patterns.
 * Derived from GitLeaks (MIT) and public documentation.
 */

import type { SecretPattern } from "../../types";

export const DOCKER_HUB_TOKEN: SecretPattern = {
  secretType: "DOCKER_HUB_TOKEN",
  patterns: [
    /dckr_pat_[A-Za-z0-9_-]{27,}/g,
    /(?:DOCKER_PASSWORD|DOCKERHUB_TOKEN)\s*[:=]\s*["']?([A-Za-z0-9_-]{36,})["']?/g,
  ],
};

export const DOCKER_REGISTRY_AUTH: SecretPattern = {
  secretType: "DOCKER_REGISTRY_AUTH",
  patterns: [/"auth"\s*:\s*"([A-Za-z0-9+/=]{20,})"/g],
  minEntropy: 3.5,
};

export const KUBERNETES_SERVICE_TOKEN: SecretPattern = {
  secretType: "KUBERNETES_SERVICE_TOKEN",
  patterns: [/(?:KUBERNETES_TOKEN|K8S_TOKEN|KUBE_TOKEN)\s*[:=]\s*["']?([A-Za-z0-9_-]{100,})["']?/g],
  minEntropy: 4.0,
};

export const TERRAFORM_TOKEN: SecretPattern = {
  secretType: "TERRAFORM_TOKEN",
  patterns: [
    /[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,}/g,
    /(?:TF_TOKEN|TFC_TOKEN|TERRAFORM_TOKEN)\s*[:=]\s*["']?([A-Za-z0-9._-]{40,})["']?/g,
  ],
};

export const VAULT_TOKEN: SecretPattern = {
  secretType: "VAULT_TOKEN",
  patterns: [
    /hvs\.[A-Za-z0-9_-]{24,}/g,
    /(?:VAULT_TOKEN)\s*[:=]\s*["']?([a-z0-9.-]{20,})["']?/g,
  ],
};

export const CONSUL_TOKEN: SecretPattern = {
  secretType: "CONSUL_TOKEN",
  patterns: [/(?:CONSUL_TOKEN|CONSUL_HTTP_TOKEN)\s*[:=]\s*["']?([a-f0-9-]{36})["']?/g],
};

export const PULUMI_TOKEN: SecretPattern = {
  secretType: "PULUMI_TOKEN",
  patterns: [/pul-[A-Za-z0-9]{40}/g],
};

export const ANSIBLE_VAULT_PASSWORD: SecretPattern = {
  secretType: "ANSIBLE_VAULT_PASSWORD",
  patterns: [/\$ANSIBLE_VAULT;[0-9.]+;AES256/g],
};

export const HELM_REPO_TOKEN: SecretPattern = {
  secretType: "HELM_REPO_TOKEN",
  patterns: [/(?:HELM_REPO_PASSWORD|HELM_TOKEN)\s*[:=]\s*["']?([A-Za-z0-9_-]{20,})["']?/g],
  minEntropy: 3.5,
};

export const GRAFANA_API_KEY: SecretPattern = {
  secretType: "GRAFANA_API_KEY",
  patterns: [
    /eyJrIjoi[A-Za-z0-9_-]{30,}/g,
    /glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}/g,
    /glc_[A-Za-z0-9+/]{32,}={0,2}/g,
  ],
};

export const INFRASTRUCTURE_PATTERNS: SecretPattern[] = [
  DOCKER_HUB_TOKEN,
  DOCKER_REGISTRY_AUTH,
  KUBERNETES_SERVICE_TOKEN,
  TERRAFORM_TOKEN,
  VAULT_TOKEN,
  CONSUL_TOKEN,
  PULUMI_TOKEN,
  ANSIBLE_VAULT_PASSWORD,
  HELM_REPO_TOKEN,
  GRAFANA_API_KEY,
];
