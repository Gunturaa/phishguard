"use client";

import { useState, useEffect } from "react";
import {
  ArrowUpRight,
  CheckCircle2,
  ChevronRight,
  CircleGauge,
  Copy,
  ExternalLink,
  Fingerprint,
  Globe2,
  History,
  Link2,
  LoaderCircle,
  LockKeyhole,
  Radar,
  ScanSearch,
  Shield,
  ShieldAlert,
  Sparkles,
  Terminal,
  Trash2,
  X,
  Zap,
} from "lucide-react";

type ScanResult = {
  ok: boolean;
  history_id?: number;
  url?: string;
  final_status?: "SAFE" | "SUSPICIOUS" | "PHISHING";
  risk_score?: number;
  machine_learning?: { status: string; confidence: number; probabilities: { phishing: number; legitimate: number } };
  heuristic_analysis?: { status: string; risk_score: number; findings: Array<{ title: string; severity: string; description: string }>; summary: string };
  threat_intelligence?: { status: string; provider: string; details?: string };
  risk_assessment?: { conflicts: string[] };
  scan_metadata?: {
    domain: string; whois_url: string; virustotal_url: string;
    redirects: { status: string; value?: string | null; details: string };
    domain_age: { status: string; value?: string | null; details: string };
    domain_explanation: { status: string; value?: string | null; details: string };
    popularity: { status: string; value?: string | null; details: string };
    viewed_as: string; scanned_from: string; scanned_with: string;
    page_title: { status: string; value?: string | null; details: string };
  };
  recommendations?: string[];
  error?: string;
};

type HistoryItem = {
  url: string;
  status: "SAFE" | "SUSPICIOUS" | "PHISHING";
  risk_score: number;
  timestamp: string;
};

type VulnerabilityResult = {
  status: string;
  target: string;
  http_status?: number | null;
  risk_level?: string;
  risk_ratings?: Record<string, number>;
  scan_information?: { duration_seconds: number; tests_performed: number; scan_status: string };
  redirect?: string;
  technologies?: Array<{ name: string; category: string; source: string }>;
  robots_txt?: { found: boolean; content?: string };
  findings_count: number;
  findings: Array<{ rule: string; severity: string; title: string; recommendation: string; evidence?: string }>;
  recommendations: string[];
  error?: string;
  disclaimer: string;
};

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL || "http://127.0.0.1:8000";

const SAMPLE_URLS = [
  { label: "Legitimate (Safe)", url: "https://stackoverflow.com/questions/tagged/php", type: "safe" },
  { label: "Suspicious Hosting", url: "https://keraekken-loagginnusa.godaddysites.com/", type: "suspicious" },
  { label: "High-Risk Executable", url: "http://8.8.8.8/download.exe", type: "phishing" },
];

function MetaItem({ label, value, wide = false }: { label: string; value?: string | null; wide?: boolean }) {
  return <div className={`meta-item${wide ? " meta-wide" : ""}`}><span>{label}</span><strong>{value || "Unavailable"}</strong></div>;
}

export default function Home() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [terminalOpen, setTerminalOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const [vulnLoading, setVulnLoading] = useState(false);
  const [vulnAuthorized, setVulnAuthorized] = useState(false);
  const [vulnResult, setVulnResult] = useState<VulnerabilityResult | null>(null);

  // Load history from localStorage
  useEffect(() => {
    try {
      const stored = localStorage.getItem("phishguard_history");
      if (stored) {
        setHistory(JSON.parse(stored));
      }
    } catch {
      // ignore
    }
  }, []);

  function saveToHistory(item: HistoryItem) {
    setHistory((prev) => {
      const updated = [item, ...prev.filter((h) => h.url !== item.url)].slice(0, 8);
      try {
        localStorage.setItem("phishguard_history", JSON.stringify(updated));
      } catch {
        // ignore
      }
      return updated;
    });
  }

  function clearHistory() {
    setHistory([]);
    try {
      localStorage.removeItem("phishguard_history");
    } catch {
      // ignore
    }
  }

  async function triggerScan(targetUrl: string) {
    if (!targetUrl.trim()) {
      setResult({ ok: false, error: "Masukkan URL terlebih dahulu." });
      return;
    }
    setResult(null);
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: targetUrl }),
      });
      const data: ScanResult = await response.json();
      if (response.ok && data.ok) {
        setResult(data);
        if (data.final_status && data.risk_score !== undefined) {
          saveToHistory({
            url: data.url || targetUrl,
            status: data.final_status,
            risk_score: data.risk_score,
            timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
          });
        }
      } else {
        setResult({ ok: false, error: data.error || "URL tidak dapat diproses." });
      }
    } catch {
      setResult({ ok: false, error: "Tidak dapat terhubung ke API. Pastikan backend berjalan di port 8000." });
    } finally {
      setLoading(false);
    }
  }

  function handleScan(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    triggerScan(url);
  }

  async function runVulnerabilityCheck() {
    if (!url.trim() || !vulnAuthorized) return;
    setVulnLoading(true);
    setVulnResult(null);
    try {
      const response = await fetch(`${API_BASE}/web-vuln-check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, authorized: true }),
      });
      const data: VulnerabilityResult = await response.json();
      setVulnResult(response.ok ? data : { ...data, status: "ERROR", error: data.error || "Pemeriksaan gagal." });
    } catch {
      setVulnResult({
        status: "UNAVAILABLE",
        target: url,
        findings_count: 0,
        findings: [],
        recommendations: [],
        error: "Backend tidak dapat dihubungi.",
        disclaimer: "Pemeriksaan pasif terbatas.",
      });
    } finally {
      setVulnLoading(false);
    }
  }

  function copyReport() {
    if (!result) return;
    const reportText = `[PHISHGUARD SECURITY REPORT]
Target: ${result.url}
Verdict: ${result.final_status} (Risk Score: ${result.risk_score}/100)
ML Status: ${result.machine_learning?.status} (${Math.round((result.machine_learning?.confidence || 0) * 100)}% conf)
Heuristics: ${result.heuristic_analysis?.findings.length || 0} findings
Threat Intel: ${result.threat_intelligence?.status} (${result.threat_intelligence?.provider})
Date: ${new Date().toLocaleString()}`;

    navigator.clipboard.writeText(reportText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  function downloadPdfReport() {
    if (!result?.history_id) return;
    window.open(`${API_BASE}/history/${result.history_id}/report.pdf`, "_blank", "noopener,noreferrer");
  }

  // Parse breakdown of URL
  function renderUrlBreakdown(rawUrl?: string) {
    if (!rawUrl) return null;
    try {
      const parsed = new URL(rawUrl);
      return (
        <div className="url-breakdown">
          <span className="badge-part scheme">{parsed.protocol}</span>
          <span className="badge-part host">{parsed.hostname}</span>
          {parsed.pathname && parsed.pathname !== "/" && <span className="badge-part path">{parsed.pathname}</span>}
          {parsed.search && <span className="badge-part search">{parsed.search}</span>}
        </div>
      );
    } catch {
      return null;
    }
  }

  const metadata = result?.scan_metadata;
  const status = result?.final_status?.toLowerCase() || "safe";

  return (
    <main className="app-shell">
      <header className="topbar">
        <a className="brand" href="#">
          <span className="brand-mark"><Shield size={18} /></span>
          <span>PHISH<span className="brand-accent">GUARD</span></span>
        </a>
        <div className="topbar-right">
          <span className="live-indicator"><i /> Live system</span>
          <span className="topbar-divider" />
          <span className="mono">v1.0.0</span>
          <button
            className={`icon-button ${terminalOpen ? "active" : ""}`}
            aria-label="Inspect raw JSON"
            title="Inspect Raw JSON / Terminal"
            onClick={() => setTerminalOpen(!terminalOpen)}
          >
            <Terminal size={17} />
          </button>
        </div>
      </header>

      <section className="hero-grid">
        <div className="hero-copy-block">
          <div className="eyebrow"><Radar size={14} /> HYBRID THREAT INTELLIGENCE <span>•</span> 16 SIGNALS</div>
          <h1>Know what&apos;s<br /><em>behind the link.</em></h1>
          <p>Investigate suspicious URLs with three independent layers of protection. Fast signals, transparent reasoning, safer decisions.</p>
          <div className="hero-stats">
            <div><strong>03</strong><span>Detection layers</span></div>
            <div><strong>100</strong><span>Risk score scale</span></div>
            <div><strong>{history.length}</strong><span>Recent scans</span></div>
          </div>
        </div>
        <div className="signal-orbit" aria-hidden="true">
          <div className="orbit orbit-one" />
          <div className="orbit orbit-two" />
          <div className="orbit-core"><Shield size={36} /><span>PG</span></div>
          <span className="orbit-tag tag-top">ML ENGINE</span>
          <span className="orbit-tag tag-right">WEB RISK</span>
          <span className="orbit-tag tag-bottom">HEURISTICS</span>
        </div>
      </section>

      <section className="workspace-grid">
        <div className="scanner-panel panel">
          <div className="panel-heading">
            <div>
              <span className="section-kicker">01 / SCAN TARGET</span>
              <h2>Analyze a URL</h2>
            </div>
            <span className="secure-badge"><LockKeyhole size={13} /> passive scan</span>
          </div>

          <form onSubmit={handleScan}>
            <label className="field-label" htmlFor="url-input">Target URL</label>
            <div className="url-field">
              <Link2 size={18} />
              <input
                id="url-input"
                value={url}
                onChange={(event) => setUrl(event.target.value)}
                placeholder="https://example.com"
                maxLength={2048}
                autoComplete="url"
              />
              <span className="mono">URL</span>
            </div>
            <button className="scan-button" disabled={loading}>
              {loading ? (
                <><LoaderCircle className="spin" size={18} /> Analyzing signals...</>
              ) : (
                <><ScanSearch size={18} /> Scan URL <ArrowUpRight size={17} /></>
              )}
            </button>
          </form>

          {/* Sample URLs for Quick Testing */}
          <div className="sample-strip">
            <span className="sample-label">Try sample:</span>
            {SAMPLE_URLS.map((sample) => (
              <button
                key={sample.label}
                type="button"
                className={`sample-pill pill-${sample.type}`}
                onClick={() => {
                  setUrl(sample.url);
                  triggerScan(sample.url);
                }}
              >
                {sample.label}
              </button>
            ))}
          </div>

          <div className="privacy-note">
            <CheckCircle2 size={14} /> No automatic navigation <span>·</span> <CheckCircle2 size={14} /> API keys stay server-side
          </div>
          <div className="vuln-tools">
            <label><input type="checkbox" checked={vulnAuthorized} onChange={(event) => setVulnAuthorized(event.target.checked)} /> Saya memiliki izin untuk memeriksa target ini</label>
            <button type="button" className="vuln-button" disabled={!vulnAuthorized || vulnLoading || !url.trim()} onClick={runVulnerabilityCheck}>
              {vulnLoading ? <><LoaderCircle className="spin" size={15} /> Checking security...</> : <><ShieldAlert size={15} /> Passive web vulnerability check</>}
            </button>
          </div>
          {vulnResult && <div className={`vuln-result vuln-${vulnResult.status.toLowerCase()}`} role="status">
            <div className="vuln-result-head"><strong>WEB SECURITY: {vulnResult.status}</strong><span>{vulnResult.findings_count} findings</span></div>
            {vulnResult.risk_ratings && <div className="vuln-summary"><strong>Overall risk: {vulnResult.risk_level}</strong><span>Critical {vulnResult.risk_ratings.CRITICAL || 0}</span><span>High {vulnResult.risk_ratings.HIGH || 0}</span><span>Medium {vulnResult.risk_ratings.MEDIUM || 0}</span><span>Low {vulnResult.risk_ratings.LOW || 0}</span><span>Info {vulnResult.risk_ratings.INFO || 0}</span></div>}
            {vulnResult.scan_information && <div className="vuln-scan-info"><span>{vulnResult.scan_information.tests_performed} checks</span><span>{vulnResult.scan_information.duration_seconds}s</span><span>HTTP {vulnResult.http_status || "—"}</span><span>{vulnResult.redirect}</span></div>}
            {vulnResult.technologies?.length ? <div className="vuln-tech"><span className="vuln-label">TECHNOLOGY FINGERPRINT</span>{vulnResult.technologies.map((technology) => <span key={`${technology.category}-${technology.name}`}>{technology.name} <small>{technology.category}</small></span>)}</div> : null}
            {vulnResult.robots_txt?.found && <div className="vuln-robots"><strong>robots.txt found</strong><small>Review entries manually; robots.txt is not an access control.</small></div>}
            {vulnResult.error ? <p>{vulnResult.error}</p> : vulnResult.findings.map((finding) => <div className="vuln-finding" key={finding.rule}><span className={`severity severity-${finding.severity.toLowerCase()}`}>{finding.severity}</span><div><strong>{finding.title}</strong><p>{finding.recommendation}</p>{finding.evidence && <code>{finding.evidence}</code>}</div></div>)}
            <small>{vulnResult.disclaimer}</small>
          </div>}

          {result && !result.ok && (
            <div className="error-box" role="alert">
              <ShieldAlert size={18} />
              <div>
                <strong>Scan could not be completed</strong>
                <p>{result.error}</p>
              </div>
            </div>
          )}
        </div>

        <aside className="layers-panel panel">
          <div className="panel-heading">
            <div>
              <span className="section-kicker">02 / DETECTION STACK</span>
              <h2>Three layers</h2>
            </div>
            <Zap size={18} className="accent-icon" />
          </div>

          <div className="layer-list">
            <div>
              <span className="layer-icon purple"><Fingerprint size={17} /></span>
              <span><strong>Machine learning</strong><small>Random Forest classifier</small></span>
              <i>01</i>
            </div>
            <div>
              <span className="layer-icon cyan"><CircleGauge size={17} /></span>
              <span><strong>Heuristic analysis</strong><small>Transparent URL signals</small></span>
              <i>02</i>
            </div>
            <div>
              <span className="layer-icon green"><Globe2 size={17} /></span>
              <span><strong>Threat intelligence</strong><small>Configured reputation providers</small></span>
              <i>03</i>
            </div>
          </div>

          {/* Recent Scans Widget */}
          <div className="history-widget">
            <div className="history-head">
              <span className="mono"><History size={12} /> RECENT SCANS</span>
              {history.length > 0 && (
                <button onClick={clearHistory} className="clear-btn" title="Clear history">
                  <Trash2 size={12} />
                </button>
              )}
            </div>
            {history.length === 0 ? (
              <p className="history-empty">No URLs scanned yet in this session.</p>
            ) : (
              <div className="history-list">
                {history.map((item, idx) => (
                  <div
                    key={`${item.url}-${idx}`}
                    className="history-item"
                    onClick={() => {
                      setUrl(item.url);
                      triggerScan(item.url);
                    }}
                  >
                    <span className={`status-tag status-${item.status.toLowerCase()}`}>
                      {item.status}
                    </span>
                    <span className="history-url" title={item.url}>{item.url}</span>
                    <span className="history-score">{item.risk_score}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </aside>
      </section>

      {/* RAW JSON / TERMINAL DRAWER */}
      {terminalOpen && (
        <section className="terminal-panel panel">
          <div className="panel-heading">
            <div className="flex-row">
              <Terminal size={16} />
              <span className="section-kicker">SYSTEM TELEMETRY / RAW RESPONSE</span>
            </div>
            <button className="icon-close" onClick={() => setTerminalOpen(false)}>
              <X size={16} />
            </button>
          </div>
          <pre className="terminal-output">
            {result ? JSON.stringify(result, null, 2) : "// Belum ada pemindaian. Jalankan scan URL untuk melihat output JSON."}
          </pre>
        </section>
      )}

      {/* SCAN RESULTS */}
      {result?.ok && (
        <section className={`results-panel panel result-${status}`} aria-live="polite">
          <div className="result-banner">
            <div>
              <span className="section-kicker">03 / FINAL ASSESSMENT</span>
              <div className="verdict-row">
                <span className="verdict-dot" />
                <h2>{result.final_status}</h2>
                <button className="copy-report-btn" onClick={copyReport} title="Copy summary to clipboard">
                  {copied ? <CheckCircle2 size={14} /> : <Copy size={14} />}
                  <span>{copied ? "Copied!" : "Copy Report"}</span>
                </button>
                <button className="copy-report-btn" onClick={downloadPdfReport} disabled={!result.history_id} title="Download PDF report">
                  <ExternalLink size={14} />
                  <span>PDF Report</span>
                </button>
              </div>
              <p className="raw-url-text">{result.url}</p>
              {renderUrlBreakdown(result.url)}
            </div>
            <div className="score-ring">
              <strong>{result.risk_score}</strong>
              <span>RISK / 100</span>
            </div>
          </div>

          <div className="analysis-grid">
            <div className="analysis-card">
              <Fingerprint size={16} />
              <span>Machine learning</span>
              <strong>{result.machine_learning?.status}</strong>
              <small>{Math.round((result.machine_learning?.confidence || 0) * 100)}% confidence</small>
            </div>
            <div className="analysis-card">
              <CircleGauge size={16} />
              <span>Heuristics</span>
              <strong>{result.heuristic_analysis?.status}</strong>
              <small>{result.heuristic_analysis?.risk_score}/100 · {result.heuristic_analysis?.findings.length} findings</small>
            </div>
            <div className="analysis-card">
              <Globe2 size={16} />
              <span>Threat intelligence</span>
              <strong>{result.threat_intelligence?.status}</strong>
              <small>{result.threat_intelligence?.provider}</small>
            </div>
          </div>

          {metadata && (
            <div className="metadata-section">
              <div className="subheading">
                <span className="section-kicker">LINK INTELLIGENCE</span>
                <div>
                  <a href={metadata.whois_url} target="_blank" rel="noreferrer">Whois <ExternalLink size={12} /></a>
                  <a href={metadata.virustotal_url} target="_blank" rel="noreferrer">VirusTotal <ExternalLink size={12} /></a>
                </div>
              </div>
              <div className="metadata-grid">
                <MetaItem label="Domain" value={metadata.domain} />
                <MetaItem label="Redirects to" value={metadata.redirects.value || metadata.redirects.status} />
                <MetaItem label="Domain age" value={metadata.domain_age.value || metadata.domain_age.status} />
                <MetaItem label="Popularity" value={metadata.popularity.value || metadata.popularity.status} />
                <MetaItem label="Viewed as" value={metadata.viewed_as} />
                <MetaItem label="Scanned from" value={metadata.scanned_from} />
                <MetaItem label="Scanned with" value={metadata.scanned_with} />
                <MetaItem label="Page title" value={metadata.page_title.value || metadata.page_title.status} wide />
                <MetaItem label="Domain explanation" value={metadata.domain_explanation.value || metadata.domain_explanation.status} wide />
              </div>
            </div>
          )}

          <div className="result-columns">
            <div>
              {result.heuristic_analysis?.findings.length ? (
                <div className="detail-block">
                  <span className="section-kicker">DETECTION REASONS</span>
                  {result.heuristic_analysis.findings.map((finding) => (
                    <div className="finding" key={`${finding.title}-${finding.description}`}>
                      <span className={`severity severity-${finding.severity.toLowerCase()}`}>{finding.severity}</span>
                      <div>
                        <strong>{finding.title}</strong>
                        <p>{finding.description}</p>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="empty-state">
                  <CheckCircle2 size={18} />
                  <span>No heuristic indicators found.</span>
                </div>
              )}
            </div>

            <div className="detail-block">
              <span className="section-kicker">RECOMMENDED ACTIONS</span>
              {result.recommendations?.map((recommendation) => (
                <div className="recommendation" key={recommendation}>
                  <ChevronRight size={14} />
                  <p>{recommendation}</p>
                </div>
              ))}
              {result.risk_assessment?.conflicts.length ? (
                <div className="conflict-note">
                  <strong>Signal conflict</strong>
                  {result.risk_assessment.conflicts.map((conflict) => (
                    <p key={conflict}>{conflict}</p>
                  ))}
                </div>
              ) : null}
            </div>
          </div>
        </section>
      )}

      <section className="bottom-section">
        <div>
          <span className="section-kicker">WHY PHISHGUARD</span>
          <h2>Signal over guesswork.</h2>
        </div>
        <p>Setiap keputusan disertai bukti yang dapat dibaca manusia. Hasil ini adalah indikasi risiko, bukan jaminan keamanan mutlak.</p>
        <span className="mono build-label"><Sparkles size={13} /> BUILD 2026.11</span>
      </section>

      <footer>
        <span className="brand mini">
          <span className="brand-mark"><Shield size={14} /></span>
          PHISH<span className="brand-accent">GUARD</span>
        </span>
        <span className="mono">BUILT FOR SAFER BROWSING</span>
      </footer>
       </main>
  );
}
