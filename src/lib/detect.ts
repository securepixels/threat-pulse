export function detectType(v: string): 'ip' | 'domain' | 'hash' | null {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return 'ip'
  if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(v)) return 'hash'
  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$/.test(v)) return 'domain'
  return null
}
