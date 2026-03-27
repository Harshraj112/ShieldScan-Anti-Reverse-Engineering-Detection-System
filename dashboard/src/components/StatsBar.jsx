import styles from './StatsBar.module.css'
export default function StatsBar({ stats }) {
  const topType = stats.byType
    ? Object.entries(stats.byType).sort((a,b) => b[1]-a[1])[0]
    : null
  const topDomain = stats.byDomain
    ? Object.entries(stats.byDomain).sort((a,b) => b[1]-a[1])[0]
    : null
  return (
    <div className={styles.bar}>
      <MetricCard color="danger" label="Total Threats" value={stats.total ?? 0} sub="all time" />
      <MetricCard color="warn"   label="Today" value={stats.todayCount ?? 0} sub="violations today" />
      <MetricCard color="accent" label="Unique IPs" value={stats.uniqueIps ?? 0} sub="distinct visitors" />
      <MetricCard color="safe"   label="Blocked IPs" value={stats.blockedIps ?? 0} sub="currently blocked" />
      <MetricCard color="warn"   label="Top Violation"
        value={topType ? topType[0] : '—'}
        sub={topType ? `×${topType[1]}` : 'none yet'} small />
      <MetricCard color="accent" label="Top Target"
        value={topDomain ? topDomain[0] : '—'}
        sub={topDomain ? `×${topDomain[1]} hits` : 'none yet'} small />
    </div>
  )
}
function MetricCard({ color, label, value, sub, small }) {
  return (
    <div className={`${styles.card} ${styles[color]}`}>
      <div className={styles.label}>{label}</div>
      <div className={`${styles.value} ${small ? styles.valueSmall : ''}`}>{value}</div>
      <div className={styles.sub}>{sub}</div>
    </div>
  )
}
