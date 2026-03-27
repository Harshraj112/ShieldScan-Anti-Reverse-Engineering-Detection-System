import { useState } from 'react'
import LoginPage from './components/LoginPage.jsx'
import Dashboard from './components/Dashboard.jsx'
export default function App() {
  const [token, setToken] = useState(() => sessionStorage.getItem('ss_dash_token') || '')
  function handleLogin(tok) {
    sessionStorage.setItem('ss_dash_token', tok)
    setToken(tok)
  }
  function handleLogout() {
    sessionStorage.removeItem('ss_dash_token')
    setToken('')
  }
  if (!token) return (
    <>
      <div className="bg-mesh"></div>
      <div className="scanline"></div>
      <LoginPage onLogin={handleLogin} />
    </>
  )
  return (
    <>
      <div className="bg-mesh"></div>
      <div className="scanline"></div>
      <Dashboard token={token} onLogout={handleLogout} />
    </>
  )
}
