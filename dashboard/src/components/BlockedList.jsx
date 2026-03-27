import { useState, useEffect } from 'react'
import styles from './BlockedList.module.css'
export default function BlockedList({ token, onUnblock }) {
  const [blocked, setBlocked] = useState({})
  const [loading, setLoading] = useState(true)
  useEffect(() => {
    fetchBlocked()
  }, [])
  async function fetchBlocked() {
    setLoading(true)
    try {
      const res = await fetch('/api/blocked', {
        headers: { 'x-shieldscan-token': token }
      })
      const data = await res.json()
      setBlocked(data.blocked || {})
    } catch(e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }
  const ips = Object.keys(blocked)
  if (loading) return <div className={styles.empty}>Loading blocked IPs…</div>
  if (ips.length === 0) return <div className={styles.empty}>No IPs are currently blocked.</div>
  return (
    <div className={styles.container}>
      <h2 className={styles.title}>List of Explicitly Blocked IPs</h2>
      <p className={styles.subtitle}>These IPs will see the Access Blocked overlay immediately upon visiting any protected page.</p>
      <div className={styles.grid}>
        {ips.map(ip => {
          const info = blocked[ip]
          return (
            <div key={ip} className={styles.card}>
              <div className={styles.cardHeader}>
                <span className={styles.ip}>{ip}</span>
                <button className={styles.unblockBtn} onClick={() => {
                  onUnblock(ip)
                  setTimeout(fetchBlocked, 200)
                }}>UNBLOCK</button>
              </div>
              <div className={styles.meta}>
                <div><strong>Blocked at:</strong> {new Date(info.blockedAt).toLocaleString()}</div>
                <div><strong>Reason:</strong> {info.reason}</div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
