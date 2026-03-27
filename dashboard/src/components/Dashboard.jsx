import { useState, useEffect, useCallback, useRef } from 'react'
import styles from './Dashboard.module.css'
import StatsBar from './StatsBar.jsx'
import ThreatTable from './ThreatTable.jsx'
import BlockedList from './BlockedList.jsx'

const POLL_INTERVAL = 4000

export default function Dashboard({ token, onLogout }) {
  const [view, setView]       = useState('threats')   // 'threats' | 'blocked'
  const [threats, setThreats] = useState([])
  const [stats, setStats]     = useState(null)
  const [total, setTotal]     = useState(0)
  const [loading, setLoading] = useState(true)
  const [liveCount, setLiveCount] = useState(0)
  const prevTotalRef = useRef(0)

  // Filter state
  const [filterDate,    setFilterDate]    = useState('')
  const [filterWebsite, setFilterWebsite] = useState('')
  const [filterIp,      setFilterIp]      = useState('')

  const authHeaders = { 'Content-Type': 'application/json', 'x-shieldscan-token': token }

  const fetchThreats = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    try {
      const params = new URLSearchParams({ limit: 200 })
      if (filterDate)    params.append('date',    filterDate)
      if (filterWebsite) params.append('website', filterWebsite)
      if (filterIp)      params.append('ip',      filterIp)

      const [tRes, sRes] = await Promise.all([
        fetch(`/api/threats?${params}`, { headers: authHeaders }),
        fetch('/api/stats')
      ])

      if (tRes.status === 401) { onLogout(); return; }

      const tData = await tRes.json()
      const sData = await sRes.json()

      // Count new threats since last poll
      if (prevTotalRef.current > 0 && tData.total > prevTotalRef.current) {
        setLiveCount(n => n + (tData.total - prevTotalRef.current))
        setTimeout(() => setLiveCount(0), 3000)
      }
      prevTotalRef.current = tData.total

      setThreats(tData.threats || [])
      setTotal(tData.total || 0)
      setStats(sData)
    } catch(e) {
      console.error('Poll error:', e)
    } finally {
      setLoading(false)
    }
  }, [filterDate, filterWebsite, filterIp, token])

  useEffect(() => {
    fetchThreats()
    const id = setInterval(() => fetchThreats(true), POLL_INTERVAL)
    return () => clearInterval(id)
  }, [fetchThreats])

  async function handleClearAll() {
    if (!confirm('Clear ALL threat records? This cannot be undone.')) return
    await fetch('/api/threats', { method: 'DELETE', headers: authHeaders })
    fetchThreats()
  }

  async function handleUnblockIp(ip) {
    await fetch(`/api/blocked/${encodeURIComponent(ip)}`, { method: 'DELETE', headers: authHeaders })
    fetchThreats(true)
  }

  async function handleBlockIp(ip) {
    await fetch(`/api/blocked/${encodeURIComponent(ip)}`, {
      method: 'POST', headers: authHeaders,
      body: JSON.stringify({ reason: 'Manually blocked from dashboard' })
    })
    fetchThreats(true)
  }

  const now = new Date()
  const timeStr = now.toLocaleTimeString('en-US', { hour12: false })

  return (
    <div className={styles.shell}>
      {/* ── Topbar ── */}
      <header className={styles.topbar}>
        <div className={styles.logo}>
          <span className={styles.logoIcon}>🛡</span>
          <span className={styles.logoText}>ShieldScan</span>
          <span className={styles.logoSep}>//</span>
          <span>MONITOR</span>
        </div>
        <div className={styles.topbarRight}>
          <div className={styles.clock}>{timeStr}</div>
          {liveCount > 0 && (
            <div className={styles.liveAlert}>
              ⚡ +{liveCount} new threat{liveCount !== 1 ? 's' : ''}
            </div>
          )}
          <div className={styles.statusPill}>
            <span className={styles.pulseDot}></span>
            LIVE
          </div>
          <button className={styles.logoutBtn} onClick={onLogout}>⏻ LOGOUT</button>
        </div>
      </header>

      {/* ── Stats Bar ── */}
      {stats && <StatsBar stats={stats} />}

      {/* ── View Switcher ── */}
      <div className={styles.viewBar}>
        <div className={styles.viewTabs}>
          <button
            className={`${styles.tab} ${view === 'threats' ? styles.tabActive : ''}`}
            onClick={() => setView('threats')}>
            ⚠ Threat Log <span className={styles.tabBadge}>{total}</span>
          </button>
          <button
            className={`${styles.tab} ${view === 'blocked' ? styles.tabActive : ''}`}
            onClick={() => setView('blocked')}>
            🚫 Blocked IPs
            {stats && <span className={styles.tabBadgeDanger}>{stats.blockedIps}</span>}
          </button>
        </div>

        <div className={styles.actionRight}>
          <button className={styles.clearBtn} onClick={handleClearAll}>✕ Clear All</button>
          <button className={styles.refreshBtn} onClick={() => fetchThreats()}>↺ Refresh</button>
        </div>
      </div>

      {/* ── Filters (Threats view only) ── */}
      {view === 'threats' && (
        <div className={styles.filters}>
          <div className={styles.filterGroup}>
            <label>Date</label>
            <input type="date" value={filterDate} onChange={e => setFilterDate(e.target.value)}
              className={styles.filterInput} />
          </div>
          <div className={styles.filterGroup}>
            <label>Website</label>
            <input type="text" placeholder="e.g. example.com" value={filterWebsite}
              onChange={e => setFilterWebsite(e.target.value)} className={styles.filterInput} />
          </div>
          <div className={styles.filterGroup}>
            <label>IP Address</label>
            <input type="text" placeholder="e.g. 192.168.1.1" value={filterIp}
              onChange={e => setFilterIp(e.target.value)} className={styles.filterInput} />
          </div>
          {(filterDate || filterWebsite || filterIp) && (
            <button className={styles.clearFilters}
              onClick={() => { setFilterDate(''); setFilterWebsite(''); setFilterIp('') }}>
              ✕ Clear Filters
            </button>
          )}
        </div>
      )}

      {/* ── Main Content ── */}
      <main className={styles.main}>
        {view === 'threats' && (
          <ThreatTable
            threats={threats}
            loading={loading}
            onBlock={handleBlockIp}
            onUnblock={handleUnblockIp}
            token={token}
          />
        )}
        {view === 'blocked' && (
          <BlockedList
            token={token}
            onUnblock={handleUnblockIp}
          />
        )}
      </main>
    </div>
  )
}
