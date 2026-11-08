import { useEffect,useState } from 'react'
import { apirequest } from './api'
import './App.css'

function App() {
  const [activePage, setActivePage] = useState('dashboard')
  const [scanner, setScanner] = useState('nmap')
  const [scanType, setScanType] = useState('quick')
  const [target, setTarget] = useState('')
  const [apikey, setApiKey] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [scanResult, setScanResult] = useState(null)
  const [history, setHistory] = useState([])
  const [dashboardLoading,setDashboardLoading] = useState(false)
  const [dashboardError,setDashboardError] = useState('')
  const [scannerCount,setScannerCount] = useState(null)
  const [lastRefreshed,setLastRefreshed] = useState(null)
  const [historyLoaded, setHistoryLoaded] = useState(false)
  const totalScans = history.length
  const totalFindings = history.reduce((total,scan) => {
    const findings=Array.isArray(scan.findings) ? scan.findings : []
    return total + findings.length
  },0)
  const latestScan =history.length > 0 ? history[0] : null
  const [historyLoading, setHistoryLoading] = useState(false)
  const [historyError, setHistoryError] = useState('')
  const [selectedScan,setSelectedScan] = useState(null)
  const [detailsLoading,setDetailsLoading] = useState(false)
  const [comparisonIds,setComparisonIds] = useState({
    previous_id: '',
    current_id: '',
  })
  const [comparisonResult,setComparisonResult] = useState(null)
  const [comparisonError,setComparisonError] =useState('')
  const [credentialType,setCredentialType] = useState('hash_identification')
  const [credentialTarget,setCredentialTarget] = useState('')
  const [hashfile, setHashFile] =useState('')
  const [wordlist,setWordlist]=useState('')
  const [hashmode,setHashMode]=useState('0')
  const [credentialLoading,setCredentialLoading]=useState(false)
  const [credentialError,setCredentialError] =useState('')
  const [credentialResult,setCredentialResult] =useState(null)
  

  const handleScanSubmit = async (event) => {
    event.preventDefault()
    setLoading(true)
    setError('')
    setScanResult(null)

    try {
      const result = await apirequest('/api/v1/scans', {
        method: 'POST',
        apiKey: apikey,
        body: JSON.stringify({
          scanner,
          scan_type: scanType,
          target: target.trim(),
        }),
      })
      setScanResult(result)
      await loadDashboardData()
    } catch (requestError) {
      setError(requestError.message || 'Unable to start scan.')
    } finally {
      setLoading(false)
    }
  }

  const handleCredentialSubmit = async (event) => {
    event.preventDefault()
    setCredentialLoading(true)
    setCredentialError('')
    setCredentialResult(null)
    if (!apikey.trim()) {
      setCredentialError('Enter your API key in scan center first.')
      setCredentialLoading(false)
      return
    }
    if (
      (credentialType === 'hashcat' || credentialType === "john") &&
      (!hashfile.trim() || !wordlist.trim())
    ) {
      setCredentialError('Hash file and wordlist paths are required for this scan type.'
      )
      setCredentialLoading(false)
      return
    }
    if (credentialType === 'hashcat' && !hashmode.trim()){
      setCredentialError('Hashcat mode is required.')
      setCredentialLoading(false)
      return
    }
    try {
      const result=await apirequest('/api/v1/credential-scans', {
        method:'POST',
        apiKey:apikey,
        body: JSON.stringify({
          scan_type:credentialType,
          target: credentialTarget.trim(),
          hash_file:hashfile.trim() || null,
          wordlist:wordlist.trim() || null,
          mode: credentialType === 'hashcat' ? hashmode.trim() :null,
        })
      })
      setCredentialResult(result?.result ?? result)
    } catch (requestError) {
      setCredentialError(
        requestError.message || 'Unable to run credential audit.'
      )
    } finally {
      setCredentialLoading(false)
    }
  }
  
  const loadScanHistory = async () => {
    setHistoryLoading(true)
    setHistoryError('')
    setSelectedScan(null)
    setComparisonResult(null)
    setComparisonError('')
    setComparisonIds({previous_id:'',current_id:'',})
    if (!apikey.trim()) {
      setHistoryError('Enter your API key in Scan Center first')
      setHistoryLoading(false)
      return 
    }
    try {
      const result=await apirequest('/api/v1/history',{
        method:'GET',
        apiKey:apikey,
      })
      setHistory(Array.isArray(result?.history) ? result.history : [])
    } catch (requestError) {
      setHistoryError(requestError.message || 'Unable to load scan history.')
    } finally{
      setHistoryLoading(false)
    }
  } 

  const loadScanDetails =async(scanId) => {
    if (!Number.isInteger(Number(scanId)) || Number(scanId) <= 0) {
      setHistoryError('Invalid scan ID.Please select a valid scan.')
      return
    }
    setDetailsLoading(true)
    setHistoryError('')
    setSelectedScan(null)
    setComparisonResult(null)
    setComparisonError('')
    if (!apikey.trim()) {
      setHistoryError('Enter your API key in Scan Center first.')
      setDetailsLoading(false)
      return
    }
    try {
      const result=await apirequest(`/api/v1/history/${scanId}`,
        {
          method:'GET',
          apiKey:apikey,
        }
      )
      setSelectedScan(result?.scan ?? null)
    }catch (requestError) {
      setHistoryError(requestError.message || 'Unable to load scan details' 
      )
    } finally {
      setDetailsLoading(false)
    }
  }

  const compareScanHistory = async () => {
    setComparisonError('')
    setComparisonResult(null)
    if (!apikey.trim()){
      setComparisonError('Enter your API key in Scan Center first.')
      return 
    }
    const previousId=Number(comparisonIds.previous_id)
    const currentId=Number(comparisonIds.current_id)
    if ( 
      !Number.isInteger(previousId) ||
      !Number.isInteger(currentId) ||
      previousId <=0 ||
      currentId <= 0
    ) {
      setComparisonError('Select two valid scan IDs.')
      return
    }
    if (previousId === currentId) {
      setComparisonError('Select two different scans.')
      return
    }
    const availablescanIds=new Set (
      history.map((scan ) => Number(scan.id ?? scan.scan_id))
    )
    if (!availablescanIds.has(previousId) ||
    !availablescanIds.has(currentId)
) {
  setComparisonError('One or both selected scans are no longer available.')
  return
}
    try {
      const result=await apirequest(
        `/api/v1/history/compare?previous_id=${previousId}&current_id=${currentId}`,
        {
          method: 'GET',
          apiKey: apikey,
        }
      )
        setComparisonResult(result?.comparison ?? result)
      } catch (requestError) {
        setComparisonError(requestError.message || 'Unable to compare scans.')
      
    }
  }

  const loadDashboardData = async () => {
    setHistoryLoaded(false)
    setDashboardLoading(true)
    setDashboardError('')
    try {
      const scannerResponse = await apirequest('/api/v1/scanners')
      const scannners=scannerResponse?.scanners
      setScannerCount(Array.isArray(scannners) ? scannners.length:scannners && typeof scannners === 'object' ? Object.keys(scannners).length:null)
      if (apikey.trim()) {
        const historyResponse = await apirequest('/api/v1/history',{
          method: 'GET',
          apiKey: apikey,
        })
        setHistory(Array.isArray(historyResponse?.history) ? historyResponse.history:[])
        setHistoryLoaded(true)
      }else {
        setHistory([])
      }
    }catch (requestError) {
      setDashboardError(
        requestError.message || 'Unable to load dashboard data.'
      )
    } finally {
      setLastRefreshed(new Date())
      setDashboardLoading(false)
    }
  }
  useEffect(() => {
    if (activePage === 'dashboard') {
      loadDashboardData()
    }
  },[activePage])

  return (
    <div className="app-shell">
      <header className="topbar">
        <a
          className="brand"
          href="#dashboard"
          onClick={(event) => {
            event.preventDefault()
            setActivePage('dashboard')
          }}
        >
          <span className="brand-icon">S</span>
          <span>
            SENTINAL<span className="brand-accent">X</span>
          </span>
        </a>

        <nav className="main-nav">
          <button
            className={`nav-link ${activePage === 'dashboard' ? 'active' : ''}`}
            onClick={() => {
              if (activePage === 'dashboard') {
                loadDashboardData()
              } else {
              setActivePage('dashboard')}
            }}
          >
            Dashboard
          </button>
          <button
            className={`nav-link ${activePage === 'scans' ? 'active' : ''}`}
            onClick={() => setActivePage('scans')}
          >
            Scan Center
          </button>
          <button
            className={`nav-link ${activePage === 'credentials' ? 'active' : ''}`}
            onClick={() => setActivePage('credentials')}
          >
            Credential Audit
          </button>
          <button
            className={`nav-link ${activePage === 'history' ? 'active' : ''}`}
            onClick={() => setActivePage('history')}
          >
            Scan History
          </button>
        </nav>

        <div className="system-status">
          <span className="status-dot"></span>
          <span>Security Console</span>
        </div>
      </header>

      <main className="main-content" id={activePage}>
        {activePage === 'dashboard' && (
          <>
            <section className="welcome-section">
              <div>
                <p className="eyebrow">SECURITY OPERATIONS</p>
                <h1>Security Dashboard</h1>
                <p className="subtitle">Your security assessment workspace.</p>
              </div>

              <span className="environment-label">
                <span className="status-dot"></span>
                SENTINALX Console
              </span>
              <button type="button" className='refresh-button' onClick={loadDashboardData} disabled={dashboardLoading}>{dashboardLoading ? 'Refreshing...' : '↻ Refresh Dashboard'}</button>
            </section>
            {lastRefreshed &&(
              <p className="card-note">
                Last refreshed: {lastRefreshed.toLocaleTimeString()}
              </p>
            )}
            {dashboardError && (
                <p className="dashboard-error" role="alert">{dashboardError}</p>
              )}
            <section className="overview-grid">
             <article className="overview-card">
                <p className="card-label">Total Scans</p>
                <h2>{dashboardLoading ? '...' : totalScans}</h2>
                <p className="card-note">{!apikey.trim() ? 'Enter your API key in Scan Center' : !historyLoaded && dashboardLoading ? 'Loading scan history...': totalScans === 0 ? 'No scan history available' : 'Recorded security assessments'}</p>
              </article>

              <article className="overview-card">
                <p className="card-label">Findings</p>
                <h2>{dashboardLoading ? '...' : totalFindings}</h2>
                <p className="card-note">{totalScans===0 ? 'Run a scan to discover findings': 'Findings in recorded scans'}</p>
              </article>

              <article className="overview-card">
                <p className="card-label">Scanners</p>
                <h2>{dashboardLoading ? '...' : scannerCount ?? '-'}</h2>
                <p className="card-note">{scannerCount===null ? 'Scanner information unavailable':'Supported scanner categories'}</p>
              </article>

              
              <article className="overview-card">
                <p className="card-label">Latest Scan</p>
                <h2 className="platform-value">{dashboardLoading ? 'Loading...': latestScan ? String(latestScan.status ?? 'Recorded').replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase()): 'No scans yet'}</h2>
                <p className="card-note">{latestScan
                  ? `${latestScan.scanner ?? 'Unknown scanner'} · ${latestScan.target ?? latestScan.target_url ?? 'Target unavailable'}`
                  : 'Run a scan to see activity here'}</p>
              </article>
            </section>

            <section className="panel">
              <div className="panel-heading">
                <div>
                  <h2>Welcome to SENTINALX</h2>
                  <p>Choose a workspace from the navigation above.</p>
                </div>
                <span className="panel-icon">SX</span>
              </div>

              <div className="workspace-grid">
                <button type="button" className="workspace-card" onClick={() => setActivePage('scans')}>
                  <span className="workspace-symbol">01</span>
                  <h3>Scan Center</h3>
                  <p>Configure and launch authorized security scans.</p>
                  <span className="workspace-action">Explore workspace →</span>
                </button>

                <button type="button" className="workspace-card" onClick={() => setActivePage('credentials')}>
                  <span className="workspace-symbol">02</span>
                  <h3>Credential Audit</h3>
                  <p>Access supported hash auditing workflows.</p>
                  <span className="workspace-action">Explore workspace →</span>
                </button>

                <button type="button" className="workspace-card" onClick={() => setActivePage('history')}>
                  <span className="workspace-symbol">03</span>
                  <h3>Scan History</h3>
                  <p>Review past assessments and compare results.</p>
                  <span className="workspace-action">Explore workspace →</span>
                  </button>
              </div>
            </section>
          </>
        )}

        {activePage === 'scans' && (
          <section className="panel scan-panel">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">SECURITY OPERATIONS</p>
                <h1>Scan Center</h1>
                <p>Configure and launch authorized security scans.</p>
              </div>
            </div>

            <form className="scan-form" onSubmit={handleScanSubmit}>
              <label>
                Scanner
                <select
                  value={scanner}
                  onChange={(event) => {
                    const nextScanner = event.target.value
                    setScanner(nextScanner)
                    setScanType(
                      nextScanner === 'nmap'
                        ? 'quick'
                        : nextScanner === 'nikto'
                          ? 'basic'
                          : 'default'
                    )
                  }}
                >
                  <option value="nmap">Nmap</option>
                  <option value="nikto">Nikto</option>
                  <option value="nuclei">Nuclei</option>
                </select>
              </label>

              <label>
                Scan type
                <select value={scanType} onChange={(event) => setScanType(event.target.value)}>
                  {((scanner === 'nmap')
                    ? ['quick', 'service', 'os', 'aggressive', 'full']
                    : scanner === 'nikto'
                      ? ['basic', 'ssl', 'redirects', 'info', 'injection']
                      : ['default']
                  ).map((type) => (
                    <option key={type} value={type}>
                      {type}
                      </option>
                  ))}
                </select>
              </label>

              <label>
                Authorized target
                <input
                  type="text"
                  value={target}
                  onChange={(event) => setTarget(event.target.value)}
                  placeholder="example.com or authorized IP"
                  required
                />
              </label>

              <label>
                API key
                <input
                  type="password"
                  value={apikey}
                  onChange={(event) => setApiKey(event.target.value)}
                  autoComplete="off"
                  required
                />
              </label>

              {error && <p role="alert">{error}</p>}

              <button type="submit" disabled={loading}>
                {loading ? 'Starting scan…' : 'Start scan'}
              </button>
            </form>

            {scanResult && <pre className="scan-result">{JSON.stringify(scanResult, null, 2)}</pre>}
          </section>
        )}

        {activePage === 'credentials' && (
          <section className="panel credential-page">
            <div className="panel-heading">
              <div>
                <span className="eyebrow"> SECURITY OPERATIONS</span>
                <h1>Credential Audit</h1>
                <p>Inspect authorized hashes and run credential-security checks.</p>
              </div>
            </div>
            <form className="scan-form" onSubmit={handleCredentialSubmit}>
              <div className="form-group">
                <label htmlFor="credentialType">Audit type</label>
                <select id="credentialType" value={credentialType} onChange={(event)=>{
                  setCredentialType(event.target.value)
                  setCredentialError('')
                  setCredentialResult(null)
                }}
                >
                  <option value="hash_identification">Hash identification</option>
                  <option value="hashcat">Hashcat audit</option>
                  <option value="john">John the Ripper audit</option>
                </select>
              </div>
              <div className="form-group">
                <label htmlFor="credentialTarget">Target / description</label>
                <input id="credentialTarget" value={credentialTarget} onChange={(event) => setCredentialTarget(event.target.value)}
                placeholder="Describe the authorized audit"
                required
                />
              </div>
              {credentialType !== 'hash_identification' && (
                <><div className="form-group">
                  <label htmlFor="hashFile">Hash file path</label>
                  <input id="hashFile" value={hashfile} onChange={(event) => setHashFile(event.target.value)}
                  placeholder="data/credential_inputs/hashes.txt"
                  required
                  />
                </div>
                <div className="form-group">
                  <label htmlFor="wordlist">Wordlist path</label>
                  <input id="wordlist" value={wordlist} onChange={(event)=>setWordlist(event.target.value)}
                  placeholder="data/credential_inputs/wordlist.txt"
                  required
                  />
                </div>
                </>
              )}
              {credentialType === 'hashcat' && (
                <div className="form-group">
                  <label htmlFor="hashmode">Hashcat Mode</label>
                  <input id="hashmode" type="number" min="0" value={hashmode} onChange={(event) => setHashMode(event.target.value)}
                  placeholder="0"
                  required
                  />
                  <p className="field-help">
                    Enter the Hashcat mode appropriate for your authorized hash audit.
                  </p>
                </div>
              )}
              <button type="submit" disabled={credentialLoading}>
                {credentialLoading ? 'Running audit…' : 'Run audit'}
              </button>
            </form>
            {credentialError && (
              <p className="history-error" role="alert">{credentialError}</p>
            )}
            {
              credentialResult && (
                <section className="history-details">
                  <h2> Audit Results</h2>
                  <pre className="scan-result">
                    {JSON.stringify(credentialResult,null,2)}
                  </pre>
                  </section>
              )
            }
            </section>
        )}
        {activePage === 'history' && (
          <section className="panel">
            <div className='panel-heading'>
              <div>
                <span className="eyebrow">SECURITY OPERATIONS</span>
                <h1>Scan History</h1>
                <p>Review past scans, inspect findings, and compare results.</p>
              </div>
              <button type="button" onClick={loadScanHistory} disabled={historyLoading}>
                {historyLoading ? 'Loading...' : 'Refresh History'}
              </button>
            </div>
            {historyError && (
              <p className="history-error" role="alert">{historyError}</p>
            )}
            {historyLoading && <p className="history-muted">Loading scan records...</p>}
            {!historyLoading && !historyError && history.length === 0 && (
              <div className="history-empty">
                <h3>No scans recorded yet</h3>
                <p>Run a scan from Scan Center to populate your history.</p>
              </div>
            )}
            {history.length > 0 && (
              <>
                <div className="history-summary">
                  <div>
                    <span>Total records</span>
                    <strong>{history.length}</strong>
                  </div>
                  <div>
                    <span>Completed</span>
                    <strong>
                      {history.filter((scan) => {
                        const status = String(scan.status ?? '').toLowerCase()
                        return status === 'completed' || status === 'success'
                      }).length}
                    </strong>
                  </div>
                  <div>
                    <span>With errors</span>
                    <strong>{history.filter((scan) => Boolean(scan.error)).length}</strong>
                  </div>
                </div>
                <div className="history-records">
                  {history.map((scan, index) => (
                    <article className="history-item" key={scan.id ?? scan.scan_id ?? index}>
                      <div className="history-record-top">
                        <div>
                          <span className="history-id">SCAN #{scan.id ?? scan.scan_id ?? '—'}</span>
                          <h3>{scan.target ?? scan.target_url ?? 'Unknown target'}</h3>
                        </div>
                        <span className={`history-status status-${String(scan.status ?? 'unknown').toLowerCase()}`}>
                          {scan.status ?? 'Unknown'}
                        </span>
                      </div>
                      <div className="history-metadata">
                        <div>
                          <span>Scanner</span>
                          <strong>{scan.scanner ?? scan.tool ?? 'Unknown'}</strong>
                        </div>
                        <div>
                          <span>Scan type</span>
                          <strong>{scan.scan_type ?? 'Unknown'}</strong>
                        </div>
                        <div>
                          <span>Date</span>
                          <strong>{scan.timestamp ?? 'Unknown'}</strong>
                        </div>
                        <div>
                          <span>Duration</span>
                          <strong>{scan.duration ?? 'Unknown'}</strong>
                        </div>
                      </div>
                      <div className="history-record-actions">
                        <button type="button" onClick={() => loadScanDetails(scan.id ?? scan.scan_id)}>View details</button>
                        <label className="history-select">
                          <input type="checkbox" checked={
                            String(comparisonIds.previous_id) === String(scan.id ?? scan.scan_id) ||
                            String(comparisonIds.current_id) === String(scan.id ?? scan.scan_id)
                          }
                          onChange={(event) => {
                            const checked = event.target.checked
                            const scanId = scan.id ?? scan.scan_id
                            if (!checked) {
                              setComparisonIds((ids) => ({
                                previous_id: String(ids.previous_id) === String(scanId) ? '' : ids.previous_id,
                                current_id: String(ids.current_id) === String(scanId) ? '' : ids.current_id,
                              }))
                              setComparisonResult(null)
                              setComparisonError('')
                              return
                            }
                            setComparisonIds((ids) => {
                              if (!ids.previous_id) {
                                return { ...ids, previous_id: String(scanId) }
                              }
                              if (!ids.current_id) {
                                return { ...ids, current_id: String(scanId) }
                              }
                              return { previous_id:String(scanId),current_id:'', }
                            })
                            setComparisonResult(null)
                            setComparisonError('')
                          }}
                          />
                          Select to compare
                        </label>
                      </div>
                    </article>
                  ))}
                </div>
                <section className="history-comparison">
                  <div>
                    <h2>Compare scans</h2>
                    <p>Select two scans above,then compare their findings.</p>
                  </div>
                  <div className="comparison-selected">
                    <span>Previous: {comparisonIds.previous_id || 'Not selected'}</span>
                    <span>Current: {comparisonIds.current_id|| 'Not selected'}</span>
                  </div>
                  <button
                  type="button" onClick={compareScanHistory} disabled={!comparisonIds.previous_id || !comparisonIds.current_id}
                  >
                    Compare Selected Scans
                    </button>
                  {comparisonError && (
                    <p className="history-error" role="alert">{comparisonError}</p>
                  )}
                  {comparisonResult && (
                    <pre className="scan-result">
                      {JSON.stringify(comparisonResult,null,2)}
                    </pre>
                  )}

                </section>
              </>
            )}
            {detailsLoading && (
              <p className="history-muted">Loading scan details....</p>
            )}
            {selectedScan && (
              <section className="history-details">
                <div className="history-panel-heading">
                  <h2>Scan details - #{selectedScan.id ?? selectedScan.scan_id ?? '-'}</h2>
                  <button type="button" onClick={() => setSelectedScan(null)}>
                    Close
                  </button>
                </div>
                <pre className="scan-result">{JSON.stringify(selectedScan, null, 2)}</pre>
              </section>
            )}
          </section>
        )}
      </main>
    </div>
  )
}

export default App
