import { useState } from 'react'
import styles from './LoginPage.module.css'
export default function LoginPage({ onLogin }) {
  const [pass, setPass] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const res = await fetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: pass })
      })
      const data = await res.json()
      if (res.ok && data.token) {
        onLogin(data.token)
      } else {
        setError(data.error || 'Invalid password')
      }
    } catch (err) {
      setError('Cannot connect to server. Is it running on port 3000?')
    } finally {
      setLoading(false)
    }
  }
  return (
    <div className={styles.wrap}>
      <div className={styles.card}>
        <div className={styles.icon}>🛡</div>
        <h1 className={styles.title}>ShieldScan</h1>
        <p className={styles.sub}>MONITOR DASHBOARD</p>
        <form onSubmit={handleSubmit} className={styles.form}>
          <label className={styles.label}>Dashboard Password</label>
          <input
            type="password"
            className={styles.input}
            placeholder="Enter password…"
            value={pass}
            onChange={e => setPass(e.target.value)}
            autoFocus
          />
          {error && <p className={styles.error}>✕ {error}</p>}
          <button type="submit" className={styles.btn} disabled={loading}>
            {loading ? 'AUTHENTICATING…' : 'LOGIN →'}
          </button>
        </form>
        <p className={styles.hint}>Default password: <code>admin123</code><br />Set <code>SHIELDSCAN_PASS</code> env to override</p>
      </div>
    </div>
  )
}
