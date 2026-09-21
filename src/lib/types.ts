export interface LookupResult {
  indicator: string; type: 'ip' | 'domain' | 'hash'; verdict: 'malicious' | 'suspicious' | 'clean' | 'unknown'
  confidence: number; country?: string; isp?: string; registrar?: string; fileName?: string; fileType?: string
  firstSeen: string; lastSeen: string; reports?: number; categories: string[]; sources: { name: string; detail: string }[]
}
export interface FeedItem { title: string; desc: string; sev: string; source: string; time: string }
