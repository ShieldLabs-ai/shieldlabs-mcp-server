import type { DetectionFlags } from '@shieldlabs-ai/node';

export const CURRENT_DETECTION_FLAG_KEYS = [
  'vpn',
  'proxy',
  'private_relay',
  'tor',
  'check_incomplete',
  'network_check_incomplete',
  'os_not_detected',
  'timezone_mismatch',
  'javascript_disabled',
  'os_mismatch',
  'ip_mismatch',
  'latency_test',
  'anti_detect_browser',
  'device_spoofing',
  'rate_limited',
  'incognito',
  'search_bot',
  'ai_bot',
  'browser_automation',
  'ai_browser',
] as const;
export type CurrentDetectionFlagKey = (typeof CURRENT_DETECTION_FLAG_KEYS)[number];
export type DetectionFlagKey = keyof DetectionFlags | CurrentDetectionFlagKey;

/** Plain-language description of one detection flag. */
export interface DetectionFlagInfo {
  flag: DetectionFlagKey;
  label: string;
  /** True when the flag usually comes with a weighted risk signal; false for informational flags (weight 0). */
  scored: boolean;
  meaning: string;
}

/** The 20 detection flags of contract 2026-10-13. */
export const DETECTION_FLAG_CATALOG: readonly DetectionFlagInfo[] = [
  {
    flag: 'private_relay',
    label: 'Privacy Relay',
    scored: true,
    meaning: 'The connection goes through iCloud Private Relay or a similar privacy relay.',
  },
  {
    flag: 'network_check_incomplete',
    label: 'Network Check Incomplete',
    scored: true,
    meaning: 'The network check did not complete; missing evidence is not a negative detection.',
  },
  {
    flag: 'latency_test',
    label: 'Latency test',
    scored: true,
    meaning: 'Latency-test evidence reported by the backend; do not invent a threshold.',
  },
  {
    flag: 'device_spoofing',
    label: 'Device Spoofing',
    scored: true,
    meaning: 'The backend reported device-spoofing evidence.',
  },
  {
    flag: 'rate_limited',
    label: 'Rate limited',
    scored: false,
    meaning:
      'The address is restricted for exceeding the request rate; 999 is outside the Risk Score scale.',
  },
  {
    flag: 'ai_bot',
    label: 'AI Bot',
    scored: false,
    meaning: 'AI-bot classification; it does not prove a provider or agent identity.',
  },
  {
    flag: 'ai_browser',
    label: 'AI Browser',
    scored: false,
    meaning:
      'AI-browser classification; claimed names and verified attributes are separate evidence.',
  },
  { flag: 'vpn', label: 'VPN', scored: true, meaning: 'A VPN was detected on the connection.' },
  {
    flag: 'tor',
    label: 'Tor',
    scored: true,
    meaning: 'The connection exits through the Tor network.',
  },
  {
    flag: 'proxy',
    label: 'Proxy',
    scored: true,
    meaning:
      'The connection is routed through a proxy (from a scored risk signal or IP reputation data).',
  },
  {
    flag: 'os_mismatch',
    label: 'OS Mismatch',
    scored: true,
    meaning: 'The reported operating system contradicts other evidence about the device.',
  },
  {
    flag: 'os_not_detected',
    label: 'OS not Detected',
    scored: true,
    meaning: 'The operating system could not be derived from the available evidence.',
  },
  {
    flag: 'timezone_mismatch',
    label: 'Timezone Mismatch',
    scored: true,
    meaning: 'The device timezone does not match the location of the IP address.',
  },
  {
    flag: 'anti_detect_browser',
    label: 'Anti-detect Browser',
    scored: true,
    meaning: 'Anti-detect or device-spoofing tooling is present.',
  },
  {
    flag: 'browser_automation',
    label: 'Browser Automation',
    scored: true,
    meaning: 'The browser is driven by an automation framework.',
  },
  {
    flag: 'ip_mismatch',
    label: 'IP Mismatch',
    scored: false,
    meaning:
      'The public IP and the local IP the browser reports are different addresses. This can be ordinary on mobile networks: compare public_ip.country with local_ip.country when location matters.',
  },
  {
    flag: 'incognito',
    label: 'Incognito',
    scored: false,
    meaning: 'The browser is in a private or incognito mode.',
  },
  {
    flag: 'search_bot',
    label: 'Search bot',
    scored: false,
    meaning:
      'A known search-engine crawler. Its Risk Score is set to 0 and its traffic channel is Search bot.',
  },
  {
    flag: 'javascript_disabled',
    label: 'JavaScript Disabled',
    scored: true,
    meaning:
      'The browser lacks capabilities every ordinary browser has: a headless or automated client.',
  },
  {
    flag: 'check_incomplete',
    label: 'Check Incomplete',
    scored: false,
    meaning:
      'One of the checks did not finish before the result was stored. The identification is scored on what arrived.',
  },
];

export const DETECTION_FLAG_KEYS: readonly DetectionFlagKey[] = DETECTION_FLAG_CATALOG.map(
  (info) => info.flag,
);

const BY_FLAG = new Map(DETECTION_FLAG_CATALOG.map((info) => [info.flag, info]));

export function detectionFlagInfo(flag: DetectionFlagKey): DetectionFlagInfo {
  return BY_FLAG.get(flag) as DetectionFlagInfo;
}
