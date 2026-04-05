/**
 * Prompt injection detection patterns.
 * Inspired by HAI-Guardrails. See ATTRIBUTION.md.
 */

/** Regex patterns that indicate prompt injection attempts */
export const INJECTION_PATTERNS: RegExp[] = [
  /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|commands?|directives?)/i,
  /disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|commands?)/i,
  /forget\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|commands?)/i,
  /override\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|commands?)/i,
  /you\s+are\s+now\s+(?:a|an|in)\s+/i,
  /new\s+instructions?\s*:/i,
  /system\s*:\s*/i,
  /\bDAN\s+mode\b/i,
  /\bjailbreak\b/i,
  /do\s+anything\s+now/i,
  /act\s+as\s+(?:if\s+)?(?:you\s+(?:are|were)\s+)?(?:a\s+)?/i,
  /pretend\s+(?:you\s+are|to\s+be)\s+/i,
  /(?:reveal|show|display|print|output)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)/i,
  /(?:what|repeat|tell\s+me)\s+(?:are\s+)?your\s+(?:system\s+)?(?:instructions?|prompt|rules?)/i,
  /bypass\s+(?:your\s+)?(?:safety|security|content|ethical)\s+(?:filters?|guidelines?|restrictions?|rules?)/i,
  /(?:from\s+now\s+on|starting\s+now|henceforth)\s*,?\s*(?:you\s+(?:will|shall|must|should))/i,
];

/** Known injection keyword phrases for heuristic matching */
export const INJECTION_KEYWORDS: string[] = [
  "ignore previous instructions",
  "disregard all prior instructions",
  "forget your instructions",
  "override system prompt",
  "you are now a",
  "new instructions",
  "jailbreak",
  "DAN mode",
  "do anything now",
  "bypass safety filters",
  "ignore content policy",
  "pretend you are",
  "act as if you were",
  "reveal your system prompt",
  "what are your instructions",
  "from now on you will",
  "ignore all restrictions",
  "developer mode",
  "sudo mode",
  "admin override",
  "unlock hidden features",
  "disable safety mode",
  "ignore ethical guidelines",
  "forget all rules",
  "you have no restrictions",
];

/** Patterns indicating system prompt leakage attempts */
export const LEAKAGE_PATTERNS: RegExp[] = [
  /(?:reveal|show|display|print|output|repeat|echo)\s+(?:the\s+)?(?:system\s+)?(?:prompt|instructions?)/i,
  /(?:what|tell\s+me|share)\s+(?:is\s+|are\s+)?(?:the\s+|your\s+)?(?:system\s+)?(?:prompt|instructions?|initial\s+message)/i,
  /(?:beginning|start|first\s+part)\s+of\s+(?:the\s+|your\s+)?(?:conversation|prompt|message)/i,
  /(?:copy|paste|reproduce)\s+(?:the\s+)?(?:text|content)\s+(?:above|before)/i,
  /(?:text|content|message)\s+(?:before|above|preceding)\s+(?:this|my)\s+(?:message|input)/i,
  /(?:everything|all)\s+(?:before|above|prior\s+to)\s+(?:this|my\s+message)/i,
  /repeat\s+(?:everything|all|the\s+text)\s+(?:above|before|I\s+said)/i,
];

/** Keywords for leakage heuristic matching */
export const LEAKAGE_KEYWORDS: string[] = [
  "reveal system prompt",
  "show me your instructions",
  "what is your system prompt",
  "display initial message",
  "repeat everything above",
  "copy text before my message",
  "what are your instructions",
  "print your prompt",
  "output your system message",
  "beginning of conversation",
  "share your initial instructions",
];
