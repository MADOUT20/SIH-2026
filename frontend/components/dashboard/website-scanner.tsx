"use client"

import { useState } from "react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { 
  ShieldAlert, 
  ShieldCheck, 
  Search, 
  AlertTriangle, 
  ExternalLink, 
  Flame, 
  Zap, 
  Lock, 
  Globe, 
  CheckCircle2, 
  FileWarning, 
  Bug, 
  Key, 
  Terminal,
  Activity,
  Layers
} from "lucide-react"
import { scanWebsiteUrl, respondToThreat, type UrlScanResponse } from "@/lib/api"

const DASHBOARD_REFRESH_EVENT = "netguard:dashboard-refresh"

function emitDashboardRefresh() {
  if (typeof window !== "undefined") {
    window.dispatchEvent(new Event(DASHBOARD_REFRESH_EVENT))
  }
}

const PRESET_TARGETS = [
  {
    label: "Trojan Dropper Site",
    icon: Bug,
    url: "http://malware-download-trojan.com/payload.exe",
    type: "Trojan",
    severity: "CRITICAL",
  },
  {
    label: "Phishing Bank Portal",
    icon: Key,
    url: "https://secure-login-bank-verify.xyz/account",
    type: "Phishing",
    severity: "HIGH",
  },
  {
    label: "Ransomware C2 Endpoint",
    icon: Lock,
    url: "https://ransom-lockbit-c2.cc/key-exchange",
    type: "Ransomware",
    severity: "CRITICAL",
  },
  {
    label: "Exploit Kit Landing",
    icon: Flame,
    url: "http://wicar.org/exploit-kit-test",
    type: "Exploit Kit",
    severity: "HIGH",
  },
  {
    label: "Cryptomining Script",
    icon: Zap,
    url: "https://coinhive-miner-pool.org/worker.js",
    type: "Cryptominer",
    severity: "HIGH",
  },
  {
    label: "Legitimate Corporate Host",
    icon: CheckCircle2,
    url: "https://github.com",
    type: "Safe",
    severity: "SAFE",
  },
]

export function WebsiteThreatScanner() {
  const [urlInput, setUrlInput] = useState("")
  const [scanning, setScanning] = useState(false)
  const [scanResult, setScanResult] = useState<UrlScanResponse | null>(null)
  const [blockStatus, setBlockStatus] = useState<string | null>(null)
  const [showWarningModal, setShowWarningModal] = useState(false)

  const handleScan = async (targetUrl?: string) => {
    const urlToScan = (targetUrl || urlInput).trim()
    if (!urlToScan) return

    setScanning(true)
    setBlockStatus(null)

    try {
      const result = await scanWebsiteUrl(urlToScan)
      setScanResult(result)
      setUrlInput(urlToScan)
      if (result.is_malicious) {
        setShowWarningModal(true)
        emitDashboardRefresh()
      }
    } catch (err) {
      console.error("Failed to scan website:", err)
    } finally {
      setScanning(false)
    }
  }

  const handleBlockDomain = async () => {
    if (!scanResult?.domain) return
    setBlockStatus("blocking")
    try {
      // Trigger a block response
      const threatId = `threat_scan_${Date.now()}`
      await respondToThreat(threatId, "BLOCK")
      setBlockStatus("blocked")
      emitDashboardRefresh()
    } catch (err) {
      setBlockStatus("error")
    }
  }

  return (
    <div className="space-y-6">
      {/* Search Input Card */}
      <Card className="border-border shadow-md">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <Badge className="bg-red-600 hover:bg-red-700 text-xs px-2.5 py-0.5 text-white">
                  Real-Time Threat Detection
                </Badge>
                <Badge variant="outline" className="text-xs">
                  MITRE Stage Labeling
                </Badge>
              </div>
              <CardTitle className="text-lg sm:text-xl font-bold flex items-center gap-2 mt-1">
                <Globe className="w-5 h-5 text-indigo-500" />
                Malware, Trojan & Website Threat Scanner
              </CardTitle>
              <CardDescription className="text-xs sm:text-sm">
                Enter any website, trojan URL, or test domain to immediately inspect threat classifications, MITRE ATT&CK attack stage mappings, and safety warnings.
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* URL Input Form */}
          <form 
            onSubmit={(e) => {
              e.preventDefault()
              handleScan()
            }}
            className="flex flex-col sm:flex-row gap-2"
          >
            <div className="relative flex-1">
              <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
              <Input
                type="text"
                placeholder="Enter URL or domain (e.g. trojan-site.com, phish-login.xyz, google.com)..."
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                className="pl-10 h-11 text-sm bg-slate-50 dark:bg-slate-900 border-slate-300 dark:border-slate-700 font-mono"
              />
            </div>
            <Button 
              type="submit" 
              disabled={scanning || !urlInput.trim()} 
              className="h-11 px-6 bg-indigo-600 hover:bg-indigo-700 text-white font-medium"
            >
              {scanning ? (
                <>
                  <div className="w-4 h-4 mr-2 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  Scanning Site...
                </>
              ) : (
                <>
                  <Search className="w-4 h-4 mr-2" />
                  Scan Threat
                </>
              )}
            </Button>
          </form>

          {/* Quick-test Presets */}
          <div className="space-y-2 pt-1">
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
              <Zap className="w-3.5 h-3.5 text-amber-500" />
              Quick-Test Threat Simulation Presets:
            </p>
            <div className="flex flex-wrap gap-2">
              {PRESET_TARGETS.map((target) => (
                <Button
                  key={target.label}
                  type="button"
                  size="sm"
                  variant="outline"
                  onClick={() => handleScan(target.url)}
                  disabled={scanning}
                  className={`text-xs h-8 ${
                    target.severity === "CRITICAL"
                      ? "border-red-200 dark:border-red-900 bg-red-50/60 dark:bg-red-950/20 hover:bg-red-100 text-red-700 dark:text-red-300"
                      : target.severity === "HIGH"
                      ? "border-amber-200 dark:border-amber-900 bg-amber-50/60 dark:bg-amber-950/20 hover:bg-amber-100 text-amber-700 dark:text-amber-300"
                      : "border-emerald-200 dark:border-emerald-900 bg-emerald-50/60 dark:bg-emerald-950/20 hover:bg-emerald-100 text-emerald-700 dark:text-emerald-300"
                  }`}
                >
                  <target.icon className="w-3.5 h-3.5 mr-1.5" />
                  {target.label}
                </Button>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Real-time Threat Warning Banner & Inspection Output */}
      {scanResult && (
        <div className="space-y-4">
          {scanResult.is_malicious ? (
            /* DANGER / MALWARE / TROJAN WARNING BANNER */
            <div className="rounded-2xl border-2 border-red-500 bg-gradient-to-br from-red-950/90 via-slate-900 to-red-950/80 p-5 sm:p-6 text-white shadow-2xl animate-in fade-in zoom-in-95 duration-300">
              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                <div className="flex items-start gap-3.5">
                  <div className="p-3 bg-red-500/20 border-2 border-red-500 rounded-2xl flex items-center justify-center shrink-0 shadow-lg shadow-red-500/20">
                    <ShieldAlert className="w-8 h-8 text-red-400 animate-pulse" />
                  </div>
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge className="bg-red-600 text-white font-bold tracking-wide text-xs px-2.5 py-0.5">
                        {scanResult.warning.title}
                      </Badge>
                      <Badge className="bg-purple-600 text-white font-semibold text-xs px-2.5 py-0.5">
                        {scanResult.mitre_mapping.stage_label || `Stage ${scanResult.mitre_mapping.stage_number}: ${scanResult.mitre_mapping.stage_name}`}
                      </Badge>
                      <Badge variant="outline" className="border-red-400 text-red-300 font-mono text-xs">
                        Confidence: {scanResult.confidence_percent}%
                      </Badge>
                    </div>

                    <h3 className="text-lg sm:text-xl font-extrabold text-red-300 tracking-tight mt-1">
                      {scanResult.warning.headline}
                    </h3>
                    <p className="text-slate-300 text-xs sm:text-sm max-w-2xl leading-relaxed">
                      {scanResult.warning.recommendation}
                    </p>
                  </div>
                </div>

                <div className="flex sm:flex-col gap-2 shrink-0">
                  <Button
                    onClick={handleBlockDomain}
                    disabled={blockStatus === "blocked"}
                    className="bg-red-600 hover:bg-red-700 text-white font-bold text-xs shadow-lg shadow-red-600/30"
                  >
                    {blockStatus === "blocked" ? "Domain Blocked" : "Block Domain Now"}
                  </Button>
                </div>
              </div>

              {/* Threat Classification & MITRE Attack Stage Mapping Breakdown */}
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 mt-5 pt-4 border-t border-red-800/50">
                <div className="bg-slate-900/80 p-3 rounded-xl border border-red-900/40">
                  <p className="text-[11px] uppercase tracking-wider text-slate-400">Target Host</p>
                  <p className="text-sm font-bold text-red-300 font-mono mt-1 break-all truncate" title={scanResult.domain}>
                    {scanResult.domain}
                  </p>
                </div>

                <div className="bg-slate-900/80 p-3 rounded-xl border border-red-900/40">
                  <p className="text-[11px] uppercase tracking-wider text-slate-400">Threat Category</p>
                  <p className="text-sm font-bold text-white mt-1">
                    {scanResult.threat_category}
                  </p>
                </div>

                <div className="bg-slate-900/80 p-3 rounded-xl border border-red-900/40">
                  <p className="text-[11px] uppercase tracking-wider text-slate-400">MITRE ATT&CK Stage</p>
                  <p className="text-sm font-bold text-purple-300 mt-1 flex items-center gap-1.5">
                    <Layers className="w-4 h-4 text-purple-400" />
                    {scanResult.mitre_mapping.stage_label || `Stage ${scanResult.mitre_mapping.stage_number}`}
                  </p>
                </div>

                <div className="bg-slate-900/80 p-3 rounded-xl border border-red-900/40">
                  <p className="text-[11px] uppercase tracking-wider text-slate-400">Technique ID</p>
                  <a 
                    href={scanResult.mitre_mapping.reference_url} 
                    target="_blank" 
                    rel="noreferrer"
                    className="text-sm font-bold text-indigo-400 hover:text-indigo-300 font-mono mt-1 flex items-center gap-1"
                  >
                    {scanResult.mitre_mapping.technique_id}
                    <ExternalLink className="w-3 h-3" />
                  </a>
                  <p className="text-[10px] text-slate-400 truncate">{scanResult.mitre_mapping.technique_name}</p>
                </div>
              </div>

              {/* Evidence & Prevention Steps */}
              {scanResult.evidence && scanResult.evidence.length > 0 && (
                <div className="mt-4 bg-red-950/40 p-3.5 rounded-xl border border-red-900/60 text-xs space-y-1.5">
                  <p className="font-semibold text-red-200 uppercase tracking-wider text-[11px]">
                    Identified Threat Indicators:
                  </p>
                  <ul className="space-y-1 text-slate-300">
                    {scanResult.evidence.map((item, idx) => (
                      <li key={idx} className="flex items-start gap-1.5">
                        <span className="text-red-400 font-bold">•</span>
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ) : (
            /* SAFE RESULT BANNER */
            <div className="rounded-2xl border-2 border-emerald-500 bg-emerald-50/50 dark:bg-emerald-950/30 p-5 sm:p-6 text-slate-900 dark:text-white shadow-lg animate-in fade-in duration-300">
              <div className="flex items-start gap-3.5">
                <div className="p-3 bg-emerald-500/20 border-2 border-emerald-500 rounded-2xl flex items-center justify-center shrink-0">
                  <ShieldCheck className="w-8 h-8 text-emerald-600 dark:text-emerald-400" />
                </div>
                <div className="space-y-1 flex-1">
                  <div className="flex items-center gap-2">
                    <Badge className="bg-emerald-600 text-white font-bold text-xs px-2.5 py-0.5">
                      {scanResult.warning.title}
                    </Badge>
                    <Badge variant="outline" className="border-emerald-600 text-emerald-700 dark:text-emerald-300 font-mono text-xs">
                      Score: {scanResult.threat_score} / 1.0 (Safe)
                    </Badge>
                  </div>
                  <h3 className="text-lg font-bold text-emerald-800 dark:text-emerald-300 mt-1">
                    {scanResult.warning.headline}
                  </h3>
                  <p className="text-slate-600 dark:text-slate-300 text-xs sm:text-sm">
                    {scanResult.warning.recommendation}
                  </p>

                  <div className="pt-2 text-xs text-slate-500 font-mono">
                    Scanned Host: <span className="font-semibold text-slate-800 dark:text-slate-200">{scanResult.domain}</span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
