import { NextRequest, NextResponse } from 'next/server'

export async function POST(req: NextRequest) {
  const { indicator, type } = await req.json()
  const results: Record<string, string> = {}

  // AbuseIPDB (IP only)
  if (type === 'ip' && process.env.ABUSEIPDB_API_KEY) {
    try {
      const res = await fetch(
        `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(indicator)}&maxAgeInDays=90`,
        { headers: { Key: process.env.ABUSEIPDB_API_KEY, Accept: 'application/json' } }
      )
      const data = await res.json()
      const d = data.data
      results.abuseipdb = `Score: ${d?.abuseConfidenceScore ?? 0}/100, ${d?.totalReports ?? 0} reports`
    } catch { results.abuseipdb = 'Error fetching' }
  }

  // VirusTotal
  if (process.env.VIRUSTOTAL_API_KEY) {
    try {
      const ep = type === 'ip' ? 'ip_addresses' : type === 'domain' ? 'domains' : 'files'
      const res = await fetch(
        `https://www.virustotal.com/api/v3/${ep}/${encodeURIComponent(indicator)}`,
        { headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY } }
      )
      const data = await res.json()
      const stats = data.data?.attributes?.last_analysis_stats
      if (stats) {
        const total = Object.values(stats).reduce((a: number, b) => a + (b as number), 0)
        results.virustotal = `${stats.malicious ?? 0}/${total} engines flagged`
      }
    } catch { results.virustotal = 'Error fetching' }
  }

  // AlienVault OTX
  if (process.env.OTX_API_KEY) {
    try {
      const section = type === 'ip' ? 'IPv4' : type === 'domain' ? 'domain' : 'file'
      const res = await fetch(
        `https://otx.alienvault.com/api/v1/indicators/${section}/${encodeURIComponent(indicator)}/general`,
        { headers: { 'X-OTX-API-KEY': process.env.OTX_API_KEY } }
      )
      const data = await res.json()
      results.otx = `${data.pulse_info?.count ?? 0} pulses`
    } catch { results.otx = 'Error fetching' }
  }

  return NextResponse.json({ indicator, type, sources: results })
}
