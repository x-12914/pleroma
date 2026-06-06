// Human-readable descriptions of the raw model/heuristic class names.
// The engine produces technical labels (e.g. "DoS attacks-Hulk",
// "ScanProbe-heuristic"); this maps them to plain English for the UI.

export interface ThreatInfo {
  name: string;        // short, ~20 chars max — shown in tables
  description: string; // 1-2 sentences — shown in the detail modal
  severity: 'normal' | 'suspicious' | 'malicious';
}

export const THREAT_INFO: Record<string, ThreatInfo> = {
  // --- Benign ---
  Benign: {
    name: 'Normal Traffic',
    description: 'Standard network activity with no threat indicators.',
    severity: 'normal',
  },

  // --- DoS family (CIC-IDS2018 labels) ---
  'DoS attacks-Hulk': {
    name: 'HTTP Flood Attack',
    description:
      'A flood of HTTP requests sent in rapid succession to overwhelm the web server. Often used to take a site offline.',
    severity: 'malicious',
  },
  'DoS attacks-GoldenEye': {
    name: 'GoldenEye HTTP Flood',
    description:
      'A multi-vector HTTP flood that varies request shapes to evade simple rate limits.',
    severity: 'malicious',
  },
  'DoS attacks-Slowloris': {
    name: 'Slowloris Attack',
    description:
      'Holds many connections open and drips data slowly, exhausting the server\'s connection pool.',
    severity: 'malicious',
  },
  'DoS attacks-SlowHTTPTest': {
    name: 'Slow HTTP Attack',
    description:
      'A Slowloris-style attack sending partial HTTP requests over a long period to tie up server resources.',
    severity: 'malicious',
  },

  // --- Brute force / web attacks ---
  'Brute Force -Web': {
    name: 'Login Brute Force',
    description:
      'Many failed login attempts in rapid succession trying to guess valid credentials.',
    severity: 'malicious',
  },
  'Brute Force -XSS': {
    name: 'XSS Probing',
    description:
      'Attempts to inject script payloads via form inputs, testing for cross-site scripting vulnerabilities.',
    severity: 'suspicious',
  },
  'SQL Injection': {
    name: 'SQL Injection',
    description:
      'Attempts to inject SQL commands via input fields to extract or alter database data.',
    severity: 'suspicious',
  },

  // --- Bot ---
  Bot: {
    name: 'Botnet Activity',
    description:
      'Traffic matching known command-and-control or coordinated bot communication patterns.',
    severity: 'malicious',
  },

  // --- Heuristic-detected ---
  'ScanProbe-heuristic': {
    name: 'Port Probe',
    description:
      'A single-packet probe with no follow-up — typical network reconnaissance behaviour from a scanner or attacker mapping your services.',
    severity: 'suspicious',
  },
  'SlowHeaders-heuristic': {
    name: 'Slow HTTP Attack',
    description:
      'A long-lived web connection where the client drips data and the server is barely responding — Slowloris-family signature.',
    severity: 'suspicious',
  },
  PortScan: {
    name: 'Port Scan',
    description:
      'Sequential connection attempts to many ports on the host, looking for open services and potential entry points.',
    severity: 'suspicious',
  },
};

// Engine fallbacks that aren't a real class (e.g. when the model load fails)
const RUNTIME_LABELS: Record<string, ThreatInfo> = {
  MOCK_MODE: {
    name: 'Engine Unavailable',
    description: 'The ML engine is in mock mode — artifacts failed to load. No real classification was performed.',
    severity: 'suspicious',
  },
  ERROR: {
    name: 'Classification Error',
    description: 'The classifier threw an error processing this flow. Check the backend logs.',
    severity: 'suspicious',
  },
};

export function getThreatInfo(rawClass: string | null | undefined): ThreatInfo | null {
  if (!rawClass) return null;
  if (THREAT_INFO[rawClass]) return THREAT_INFO[rawClass];
  if (RUNTIME_LABELS[rawClass]) return RUNTIME_LABELS[rawClass];
  // Unknown class — make it presentable rather than showing the raw string
  return {
    name: rawClass.replace(/[-_]/g, ' '),
    description: 'Detection from the classifier — investigate the underlying flow features for context.',
    severity: 'suspicious',
  };
}
