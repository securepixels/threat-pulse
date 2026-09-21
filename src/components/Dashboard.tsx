'use client'
import { useState } from 'react'
import { useTheme } from './ThemeProvider'
import { detectType } from '@/lib/detect'
import { DEMO_DB, FEED_DATA } from '@/lib/demo-data'
import { LookupResult } from '@/lib/types'

export function Dashboard() {
  const { toggle } = useTheme()
  const [query, setQuery] = useState('')
  const [tab, setTab] = useState<'lookup' | 'feed'>('lookup')
  const [results, setResults] = useState<LookupResult[]>([])
  const [history, setHistory] = useState<{ indicator: string; verdict: string }[]>([])
  const [openRow, setOpenRow] = useState<Set<number>>(new Set())

  function runLookup(val?: string) {
    const v = (val ?? query).trim().toLowerCase()
    if (!v) return
    const type = detectType(v)
    if (!type) return

    let r: LookupResult | undefined
    if (type === 'ip') r = DEMO_DB.ips[v]
    else if (type === 'domain') r = DEMO_DB.domains[v]
    else if (type === 'hash') r = DEMO_DB.hashes[v]

    if (!r) r = { indicator: v, type, verdict: 'unknown', confidence: 0, reports: 0, categories: [], firstSeen: 'N/A', lastSeen: 'N/A', sources: [{ name: 'AbuseIPDB', detail: 'No data' }, { name: 'OTX', detail: 'No data' }, { name: 'VirusTotal', detail: 'No data' }] }

    setResults(prev => [r!, ...prev])
    if (!history.find(h => h.indicator === v)) setHistory(prev => [{ indicator: v, verdict: r!.verdict }, ...prev])
    setTab('lookup')
    setOpenRow(new Set())
  }

  function quickSearch(v: string) { setQuery(v); runLookup(v) }
  function toggleRow(i: number) { setOpenRow(prev => { const n = new Set(prev); n.has(i) ? n.delete(i) : n.add(i); return n }) }

  const malCount = results.filter(r => r.verdict === 'malicious').length
  const vcClass: Record<string, string> = { malicious: 'v-mal', suspicious: 'v-sus', clean: 'v-cln' }
  const tcClass: Record<string, string> = { ip: 'tag-ip', domain: 'tag-domain', hash: 'tag-hash' }
  const sevClass: Record<string, string> = { crit: 'sev-crit', high: 'sev-high', med: 'sev-med' }

  return (
    <div className="soc">
      <div className="sidebar">
        <div className="sidebar-header"><div className="sidebar-logo" /><span className="sidebar-title">THREAT PULSE</span></div>
        <div className="sidebar-section">SEARCH</div>
        <div className="sidebar-search">
          <input className="sidebar-input" value={query} onChange={e => setQuery(e.target.value)} onKeyDown={e => e.key === 'Enter' && runLookup()} placeholder="IP, domain, or hash..." />
        </div>
        <div className="sidebar-section">SAMPLES</div>
        <div style={{ padding: '0 12px' }}>
          {['185.220.101.34', '8.8.8.8', '91.121.87.10', 'malware-c2.example.net', '44d88612fea8a8f36de82e1278abb02f', 'google.com'].map(s => (
            <button key={s} className="sample-btn" onClick={() => quickSearch(s)}>{s.length > 28 ? s.slice(0, 28) + '...' : s}</button>
          ))}
        </div>
        <div className="sidebar-section">HISTORY</div>
        <div>
          {history.map(h => (
            <div key={h.indicator} className="history-item" onClick={() => quickSearch(h.indicator)}>
              <span>{h.indicator.length > 22 ? h.indicator.slice(0, 22) + '...' : h.indicator}</span>
              <span className={`v-tag ${vcClass[h.verdict] || 'v-unk'}`}>{h.verdict.slice(0, 3).toUpperCase()}</span>
            </div>
          ))}
        </div>
        <div className="sidebar-footer">built by Chrissy<br />v1.0 &middot; demo mode</div>
      </div>

      <div className="main-panel">
        <div className="status-bar">
          <div className="status-left">
            <div className="status-dot" /><span className="status-label">ONLINE</span>
            <div className="status-counts"><span><b>{results.length}</b> lookups</span><span><b style={{ color: 'var(--red)' }}>{malCount}</b> malicious</span></div>
          </div>
          <button className="theme-btn" onClick={toggle}>&#9684;</button>
        </div>
        <div className="mobile-bar">
          <input className="mobile-input" value={query} onChange={e => setQuery(e.target.value)} onKeyDown={e => e.key === 'Enter' && runLookup()} placeholder="IP, domain, or hash..." />
          <button className="go-btn" onClick={() => runLookup()}>GO</button>
        </div>
        <div className="tab-bar">
          <button className={`tab ${tab === 'lookup' ? 'active' : ''}`} onClick={() => setTab('lookup')}>LOOKUPS</button>
          <button className={`tab ${tab === 'feed' ? 'active' : ''}`} onClick={() => setTab('feed')}>THREAT FEED</button>
        </div>
        <div className="content">
          {tab === 'lookup' ? (
            results.length === 0 ? (
              <div className="empty">
                No lookups yet. Search an indicator or try a sample.
                <div style={{ display: 'flex', gap: 6, justifyContent: 'center', marginTop: 12, flexWrap: 'wrap' }}>
                  <button className="try-btn" onClick={() => quickSearch('185.220.101.34')}>185.220.101.34</button>
                  <button className="try-btn" onClick={() => quickSearch('malware-c2.example.net')}>malware-c2.example.net</button>
                </div>
              </div>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table className="data-table">
                  <thead><tr><th>INDICATOR</th><th>TYPE</th><th>VERDICT</th><th>CONFIDENCE</th><th>REPORTS</th><th>LAST SEEN</th></tr></thead>
                  <tbody>
                    {results.map((r, i) => (
                      <>{/* Fragment key on outer */}
                        <tr key={`r-${i}`} onClick={() => toggleRow(i)}>
                          <td className="indicator">{r.indicator.length > 36 ? r.indicator.slice(0, 36) + '...' : r.indicator}</td>
                          <td><span className={`type-tag ${tcClass[r.type] || ''}`}>{r.type.toUpperCase()}</span></td>
                          <td><span className={`v-tag ${vcClass[r.verdict] || 'v-unk'}`}>{r.verdict.toUpperCase()}</span></td>
                          <td>{r.confidence}%</td>
                          <td>{r.reports ?? 0}</td>
                          <td style={{ fontFamily: 'var(--mono)', fontSize: 11 }}>{r.lastSeen}</td>
                        </tr>
                        <tr key={`d-${i}`} className={`detail-row ${openRow.has(i) ? 'open' : ''}`}>
                          <td colSpan={6}>
                            <div className="detail-grid">
                              <div className="detail-item"><label>INDICATOR</label><span style={{ wordBreak: 'break-all', fontFamily: 'var(--mono)' }}>{r.indicator}</span></div>
                              {r.country && <div className="detail-item"><label>COUNTRY</label><span>{r.country}</span></div>}
                              {r.isp && <div className="detail-item"><label>ISP</label><span>{r.isp}</span></div>}
                              {r.registrar && <div className="detail-item"><label>REGISTRAR</label><span>{r.registrar}</span></div>}
                              {r.fileName && <div className="detail-item"><label>FILE</label><span>{r.fileName}</span></div>}
                              <div className="detail-item"><label>FIRST SEEN</label><span style={{ fontFamily: 'var(--mono)' }}>{r.firstSeen}</span></div>
                              <div className="detail-item"><label>LAST SEEN</label><span style={{ fontFamily: 'var(--mono)' }}>{r.lastSeen}</span></div>
                            </div>
                            {r.categories.length > 0 && <div className="cat-tags">{r.categories.map(c => <span key={c} className="cat-tag">{c}</span>)}</div>}
                            {r.sources && <div style={{ marginTop: 12 }}>{r.sources.map(s => <div key={s.name} className="source-row"><span className="source-name">{s.name}</span><span className="source-detail">{s.detail}</span></div>)}</div>}
                          </td>
                        </tr>
                      </>
                    ))}
                  </tbody>
                </table>
              </div>
            )
          ) : (
            FEED_DATA.map((f, i) => (
              <div key={i} className="feed-row">
                <div className="feed-time">{f.time}</div>
                <div className="feed-body">
                  <div className="feed-title">{f.title}</div>
                  <div className="feed-desc">{f.desc}</div>
                  <div className="feed-meta">{f.source}</div>
                </div>
                <span className={`feed-sev ${sevClass[f.sev] || 'sev-med'}`}>{f.sev.toUpperCase()}</span>
              </div>
            ))
          )}
        </div>
        <div className="about">
          <div className="about-text">I wanted a single place to check indicators without bouncing between five different tabs. This tool consolidates results from open threat intelligence sources so you can see at a glance whether an IP, domain, or hash has been flagged.</div>
          <div className="about-meta">Sources: AbuseIPDB &middot; AlienVault OTX &middot; VirusTotal (demo)</div>
        </div>
      </div>
    </div>
  )
}
