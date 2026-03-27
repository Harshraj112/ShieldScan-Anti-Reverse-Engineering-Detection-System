import styles from './ThreatTable.module.css'
export default function ThreatTable({ threats, loading, onBlock, onUnblock, token }) {
  if (loading && threats.length === 0) {
    return <div className={styles.empty}>Loading threats…</div>
  }
  if (threats.length === 0) {
    return <div className={styles.empty}>No threats found matching criteria.</div>
  }
  return (
    <div className={styles.container}>
      <table className={styles.table}>
        <thead>
          <tr>
            <th>Time</th>
            <th>Type</th>
            <th>IP Address</th>
            <th>Confidence</th>
            <th>Target Website</th>
            <th>Details & Device</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {threats.map(t => (
            <tr key={t.id} className={t.status === 'DETECTED' ? styles.rowDetected : ''}>
              <td className={styles.colTime}>
                <div>{new Date(t.timestamp).toLocaleTimeString()}</div>
                <div className={styles.dateSub}>{new Date(t.timestamp).toLocaleDateString()}</div>
              </td>
              <td className={styles.colType}>
                <span className={styles.badgeDanger}>{t.violationType || t.name}</span>
              </td>
              <td className={styles.colIp}>{t.ip}</td>
              <td className={styles.colConf}>
                <div className={styles.confBar}><div style={{width: `${t.confidence}%`}} /></div>
                <span>{t.confidence}%</span>
              </td>
              <td className={styles.colWeb} title={t.url}>{t.website || 'Unknown'}</td>
              <td className={styles.colDetail}>
                <div className={styles.detailText} title={t.detail}>{t.detail}</div>
                <div className={styles.deviceText} title={t.userAgent}>{t.userAgent}</div>
              </td>
              <td className={styles.colAction}>
                {t.autoBlocked ? (
                  <button className={styles.unblockBtn} onClick={() => onUnblock(t.ip)}>UNBLOCK</button>
                ) : (
                  <button className={styles.blockBtn} onClick={() => onBlock(t.ip)}>BLOCK IP</button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
