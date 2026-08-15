import { useEffect, useMemo, useState } from 'react'
import { Activity, AlertTriangle, Bot, Database, LockKeyhole, RefreshCw, ShieldCheck, Siren, Sparkles, Undo2 } from 'lucide-react'

const API_BASE = import.meta.env.VITE_APXOR_API_URL || ''

const NAV = [
  ['overview', 'Overview'],
  ['security', 'Security Center'],
  ['incidents', 'Incidents'],
  ['events', 'Events'],
  ['recovery', 'Recovery'],
  ['snapshots', 'Snapshots'],
  ['ai', 'AI Security'],
]

function api(path) {
  return fetch(`${API_BASE}${path}`, { credentials: 'include', headers: { Accept: 'application/json' } })
}

function Login({ configured }) {
  return (
    <main className="login-shell">
      <div className="login-card">
        <div className="brand-mark"><ShieldCheck size={28} /></div>
        <span className="eyebrow">SECURITY-FIRST DISCORD PROTECTION</span>
        <h1>APXOR Security Center</h1>
        <p>Monitor anti-nuke protection, incidents, recovery and AI threat analysis from one authenticated console.</p>
        <a className="primary-button" href={`${API_BASE}/api/dashboard/auth/login`}>Continue with Discord</a>
        {!configured && <small>Set VITE_APXOR_API_URL when the dashboard is hosted separately from the API.</small>}
      </div>
    </main>
  )
}

function Stat({ icon: Icon, label, value, tone = '' }) {
  return <div className="stat-card"><div className={`icon-box ${tone}`}><Icon size={18} /></div><div><span>{label}</span><strong>{value}</strong></div></div>
}

function StateBadge({ state }) {
  const normalized = String(state || 'UNKNOWN').toUpperCase()
  return <span className={`badge ${normalized === 'PROTECTED' ? 'good' : normalized === 'LOCKDOWN' || normalized === 'EMERGENCY' ? 'danger' : 'warn'}`}>{normalized}</span>
}

export default function App() {
  const [session, setSession] = useState(null)
  const [guildId, setGuildId] = useState('')
  const [view, setView] = useState('overview')
  const [data, setData] = useState(null)
  const [rows, setRows] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const loadSession = async () => {
    const response = await api('/api/dashboard/auth/me')
    if (!response.ok) throw new Error('LOGIN_REQUIRED')
    return response.json()
  }

  const load = async (selectedGuild, selectedView) => {
    if (!selectedGuild) return
    setLoading(true); setError('')
    const endpoints = {
      overview: `/api/dashboard/guilds/${selectedGuild}/overview`,
      security: `/api/dashboard/guilds/${selectedGuild}/security`,
      incidents: `/api/dashboard/guilds/${selectedGuild}/incidents`,
      events: `/api/dashboard/guilds/${selectedGuild}/events`,
      recovery: `/api/dashboard/guilds/${selectedGuild}/recovery`,
      snapshots: `/api/dashboard/guilds/${selectedGuild}/snapshots`,
      ai: `/api/dashboard/guilds/${selectedGuild}/ai`,
    }
    try {
      const response = await api(endpoints[selectedView])
      if (!response.ok) throw new Error((await response.text()) || `Request failed: ${response.status}`)
      const payload = await response.json()
      selectedView === 'overview' || selectedView === 'security' ? setData(payload) : setRows(payload)
    } catch (err) { setError(err.message) } finally { setLoading(false) }
  }

  useEffect(() => {
    loadSession().then((payload) => {
      setSession(payload)
      const first = payload.guild_ids?.[0]
      if (first) setGuildId(String(first))
    }).catch(() => setSession(false)).finally(() => setLoading(false))
  }, [])

  useEffect(() => { if (guildId) load(guildId, view) }, [guildId, view])

  const logout = async () => { await api('/api/dashboard/auth/logout', { method: 'POST' }); setSession(false) }
  const isOverview = view === 'overview'
  const protection = data?.protection || data?.security || {}
  const metrics = data?.security_metrics || {}
  const score = data?.protection?.score ?? data?.protection_score ?? 0
  const healthItems = useMemo(() => [
    ['Gateway', 'Runtime monitoring'], ['Database', 'Persistent state'], ['Audit Monitor', 'Actor correlation'],
    ['Recovery', protection.recovery_enabled ? 'Enabled' : 'Disabled'], ['AI', 'Threat analysis'],
  ], [protection.recovery_enabled])

  if (loading && session === null) return <div className="boot">Loading APXOR…</div>
  if (session === false) return <Login configured={Boolean(API_BASE)} />

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="logo"><div className="brand-mark"><ShieldCheck size={22} /></div><div><b>APXOR</b><span>Security Center</span></div></div>
        <nav>{NAV.map(([key, label]) => <button key={key} className={view === key ? 'active' : ''} onClick={() => setView(key)}>{label}</button>)}</nav>
        <div className="sidebar-bottom"><div className="mini-status"><i /> Protection engine online</div><button onClick={logout}>Sign out</button></div>
      </aside>

      <main className="content">
        <header className="topbar">
          <div><span className="eyebrow">SERVER SECURITY</span><h2>{view === 'overview' ? 'Security Overview' : NAV.find(([k]) => k === view)?.[1]}</h2></div>
          <div className="top-actions">
            <select value={guildId} onChange={(e) => setGuildId(e.target.value)}>{(session.guild_ids || []).map((id) => <option key={id} value={id}>{id}</option>)}</select>
            <button className="icon-button" onClick={() => load(guildId, view)} title="Refresh"><RefreshCw size={17} /></button>
          </div>
        </header>

        {error && <div className="error-banner"><AlertTriangle size={18} /> {error}</div>}
        {loading && <div className="loading-line" />}

        {isOverview && data && <>
          <section className="hero-card">
            <div><span className="eyebrow">{data.guild?.name || 'Discord Server'}</span><h1>Protection is <span>active</span></h1><p>APXOR is continuously evaluating permissions, destructive activity and recovery state.</p></div>
            <div className="score-ring"><strong>{score}</strong><span>score</span></div>
          </section>
          <section className="stats-grid">
            <Stat icon={Siren} label="Critical+ events" value={metrics.critical_or_higher_events ?? 0} tone="danger" />
            <Stat icon={AlertTriangle} label="Open incidents" value={metrics.open_incidents ?? 0} tone="warn" />
            <Stat icon={Undo2} label="Active recovery" value={metrics.active_recovery_actions ?? 0} />
            <Stat icon={Database} label="Snapshots" value={metrics.snapshots ?? 0} />
            <Stat icon={Sparkles} label="AI assessments" value={metrics.ai_assessments ?? 0} tone="ai" />
          </section>
          <section className="panel-grid">
            <div className="panel"><div className="panel-head"><h3>Protection state</h3><StateBadge state={protection.state} /></div><div className="checks">{[['Anti-nuke', protection.anti_nuke_enabled], ['Permission enforcement', protection.permission_enforcement_enabled], ['Lockdown', protection.lockdown_enabled], ['Recovery', protection.recovery_enabled]].map(([name, ok]) => <div key={name}><span>{name}</span><b className={ok ? 'ok' : 'off'}>{ok ? 'ENABLED' : 'OFF'}</b></div>)}</div></div>
            <div className="panel"><div className="panel-head"><h3>System health</h3><span className="badge good">ONLINE</span></div><div className="checks">{healthItems.map(([name, detail]) => <div key={name}><span>{name}<small>{detail}</small></span><b className="ok">HEALTHY</b></div>)}</div></div>
          </section>
        </>}

        {!isOverview && view === 'security' && data && <section className="panel"><div className="panel-head"><h3>{data.name}</h3><StateBadge state={data.protection_state} /></div><pre className="json-view">{JSON.stringify(data, null, 2)}</pre></section>}

        {!isOverview && view !== 'security' && <section className="table-panel"><div className="panel-head"><h3>{NAV.find(([k]) => k === view)?.[1]}</h3><span className="muted">Latest {rows.length} records</span></div><div className="table-wrap"><table><thead><tr><th>Type</th><th>Severity / Status</th><th>Actor / Resource</th><th>Risk</th><th>Time</th></tr></thead><tbody>{rows.length ? rows.map((row) => <tr key={row.id}><td><b>{row.event_type || row.incident_type || row.resource_type || row.classification || 'Snapshot'}</b><small>{row.incident_key || row.reason || row.snapshot_key || row.model || ''}</small></td><td><StateBadge state={row.severity || row.status || row.classification} /></td><td>{row.actor_id || row.original_resource_id || row.resource_id || '—'}</td><td>{row.risk_score ?? row.confidence != null ? `${row.risk_score ?? Math.round(row.confidence * 100)}%` : '—'}</td><td>{row.created_at ? new Date(row.created_at).toLocaleString() : '—'}</td></tr>) : <tr><td colSpan="5" className="empty">No records yet.</td></tr>}</tbody></table></div></section>}
      </main>
    </div>
  )
}
