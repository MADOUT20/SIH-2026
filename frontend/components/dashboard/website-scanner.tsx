"use client"

import { useState, useEffect } from "react"
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
  Layers,
  Info
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
  const [currentMode, setCurrentMode] = useState<"live" | "demo">("live")

  useEffect(() => {
    if (typeof window !== "undefined") {
      const stored = (localStorage.getItem("netguard_app_mode") as "live" | "demo") || "live"
      setCurrentMode(stored)

      const handleModeChange = (e: any) => {
        if (e.detail?.mode) {
          setCurrentMode(e.detail.mode)
        }
      }

      window.addEventListener("netguard:mode-change", handleModeChange)
      return () => window.removeEventListener("netguard:mode-change", handleModeChange)
    }
  }, [])

  const handleScan = async (targetUrl?: string) => {
    const urlToScan = (targetUrl || urlInput).trim()
    if (!urlToScan) return

    setScanning(true)
    setBlockStatus(null)

    try {
      const result = await scanWebsiteUrl(urlToScan, currentMode)
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

      {/* Real-time Threat Inspection Output */}
      {scanResult && (
        <div className="space-y-4">
          {/* Risk Level Banner */}
          {(() => {
            const riskLevel = scanResult.risk_level || (
              scanResult.threat_score >= 0.9 ? "Critical" :
              scanResult.threat_score >= 0.7 ? "High Risk" :
              scanResult.threat_score >= 0.4 ? "Medium Risk" :
              scanResult.threat_score >= 0.15 ? "Low Risk" : "Clean"
            )

            const isClean = riskLevel === "Clean"
            const isLow = riskLevel === "Low Risk"
            const isMedium = riskLevel === "Medium Risk"
            const isHigh = riskLevel === "High Risk"
            const isCritical = riskLevel === "Critical"

            let bannerBorder = "border-emerald-500"
            let bannerBg = "bg-emerald-50/50 dark:bg-emerald-950/20"
            let badgeColor = "bg-emerald-600 text-white"
            let titleColor = "text-emerald-800 dark:text-emerald-300"
            let IconComponent = ShieldCheck

            if (isCritical) {
              bannerBorder = "border-red-600"
              bannerBg = "bg-gradient-to-br from-red-950/90 via-slate-900 to-red-950/80 text-white"
              badgeColor = "bg-red-600 text-white font-bold"
              titleColor = "text-red-300"
              IconComponent = ShieldAlert
            } else if (isHigh) {
              bannerBorder = "border-orange-500"
              bannerBg = "bg-gradient-to-br from-orange-950/80 via-slate-900 to-slate-950 text-white"
              badgeColor = "bg-orange-600 text-white font-bold"
              titleColor = "text-orange-300"
              IconComponent = AlertTriangle
            } else if (isMedium) {
              bannerBorder = "border-amber-500"
              bannerBg = "bg-amber-50/50 dark:bg-amber-950/20"
              badgeColor = "bg-amber-600 text-white font-semibold"
              titleColor = "text-amber-800 dark:text-amber-300"
              IconComponent = AlertTriangle
            } else if (isLow) {
              bannerBorder = "border-sky-500"
              bannerBg = "bg-sky-50/50 dark:bg-sky-950/20"
              badgeColor = "bg-sky-600 text-white"
              titleColor = "text-sky-800 dark:text-sky-300"
              IconComponent = Info
            }

            return (
              <div className={`rounded-2xl border-2 ${bannerBorder} ${bannerBg} p-5 sm:p-6 shadow-xl animate-in fade-in duration-300`}>
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                  <div className="flex items-start gap-3.5">
                    <div className={`p-3 rounded-2xl flex items-center justify-center shrink-0 border-2 ${
                      isCritical || isHigh ? "bg-red-500/20 border-red-500 shadow-lg shadow-red-500/20" : "bg-emerald-500/20 border-emerald-500"
                    }`}>
                      <IconComponent className={`w-8 h-8 ${
                        isCritical ? "text-red-400 animate-pulse" : isHigh ? "text-orange-400" : isMedium ? "text-amber-400" : isLow ? "text-sky-400" : "text-emerald-500"
                      }`} />
                    </div>

                    <div className="space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge className={`${badgeColor} text-xs px-2.5 py-0.5`}>
                          {riskLevel.toUpperCase()}
                        </Badge>
                        <Badge variant="outline" className="font-mono text-xs">
                          Threat Score: {(scanResult.threat_score * 100).toFixed(0)}/100
                        </Badge>
                        {scanResult.is_malicious && (
                          <Badge className="bg-purple-600 text-white font-semibold text-xs px-2 py-0.5">
                            {scanResult.mitre_mapping?.stage_label || `Stage ${scanResult.mitre_mapping?.stage_number}`}
                          </Badge>
                        )}
                        <Badge variant="outline" className="text-[10px] text-slate-400 border-slate-700">
                          {scanResult.engine || "Multi-Signal Offline Heuristics"}
                        </Badge>
                      </div>

                      <h3 className={`text-lg sm:text-xl font-bold tracking-tight mt-1 ${titleColor}`}>
                        {scanResult.warning?.headline || `Scan complete for ${scanResult.domain}`}
                      </h3>

                      <p className="text-xs sm:text-sm max-w-2xl leading-relaxed text-slate-600 dark:text-slate-300">
                        {scanResult.warning?.recommendation}
                      </p>
                    </div>
                  </div>

                  {scanResult.is_malicious && (
                    <div className="flex sm:flex-col gap-2 shrink-0">
                      <Button
                        onClick={handleBlockDomain}
                        disabled={blockStatus === "blocked"}
                        className="bg-red-600 hover:bg-red-700 text-white font-bold text-xs shadow-lg shadow-red-600/30"
                      >
                        {blockStatus === "blocked" ? "Domain Blocked" : "Enforce Domain Block"}
                      </Button>
                    </div>
                  )}
                </div>

                {/* Metric Strip */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-5 pt-4 border-t border-slate-200/40 dark:border-slate-800/80">
                  <div className="bg-white/60 dark:bg-slate-900/80 p-3 rounded-xl border border-slate-200 dark:border-slate-800">
                    <p className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Target Host</p>
                    <p className="text-xs font-bold text-slate-900 dark:text-slate-100 font-mono mt-1 truncate" title={scanResult.domain}>
                      {scanResult.domain}
                    </p>
                  </div>

                  <div className="bg-white/60 dark:bg-slate-900/80 p-3 rounded-xl border border-slate-200 dark:border-slate-800">
                    <p className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Classification</p>
                    <p className="text-xs font-bold text-slate-900 dark:text-slate-100 mt-1">
                      {scanResult.threat_category}
                    </p>
                  </div>

                  <div className="bg-white/60 dark:bg-slate-900/80 p-3 rounded-xl border border-slate-200 dark:border-slate-800">
                    <p className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Severity Tier</p>
                    <p className="text-xs font-bold mt-1">
                      <span className={`px-2 py-0.5 rounded text-[10px] ${
                        isCritical ? "bg-rose-500/20 text-rose-400" :
                        isHigh ? "bg-orange-500/20 text-orange-400" :
                        isMedium ? "bg-amber-500/20 text-amber-400" :
                        isLow ? "bg-sky-500/20 text-sky-400" : "bg-emerald-500/20 text-emerald-400"
                      }`}>
                        {scanResult.severity}
                      </span>
                    </p>
                  </div>

                  <div className="bg-white/60 dark:bg-slate-900/80 p-3 rounded-xl border border-slate-200 dark:border-slate-800">
                    <p className="text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Evaluation Mode</p>
                    <p className="text-xs font-bold text-slate-900 dark:text-slate-100 mt-1 flex items-center gap-1">
                      <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
                      Offline Heuristic
                    </p>
                  </div>
                </div>

                {/* Contributing Signals & Subtle Indicators */}
                {scanResult.contributing_signals && scanResult.contributing_signals.length > 0 && (
                  <div className="mt-4 pt-4 border-t border-slate-200/40 dark:border-slate-800/80 space-y-2">
                    <p className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300 flex items-center gap-1.5">
                      <Activity className="h-3.5 w-3.5 text-indigo-500" />
                      Contributing Heuristic Signals ({scanResult.contributing_signals.length}):
                    </p>
                    <div className="grid gap-2 sm:grid-cols-2">
                      {scanResult.contributing_signals.map((sig: any, idx: number) => (
                        <div
                          key={idx}
                          className="rounded-lg border border-slate-200 bg-white/70 p-2.5 text-xs dark:border-slate-800 dark:bg-slate-900/70 space-y-1"
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-semibold text-slate-800 dark:text-slate-200">
                              {sig.name}
                            </span>
                            <Badge
                              variant="outline"
                              className={`text-[9px] px-1.5 py-0 ${
                                sig.severity === "CRITICAL" ? "border-rose-300 text-rose-600 dark:border-rose-800 dark:text-rose-400" :
                                sig.severity === "HIGH" ? "border-orange-300 text-orange-600 dark:border-orange-800 dark:text-orange-400" :
                                sig.severity === "MEDIUM" ? "border-amber-300 text-amber-600 dark:border-amber-800 dark:text-amber-400" :
                                sig.severity === "CLEAN" ? "border-emerald-300 text-emerald-600 dark:border-emerald-800 dark:text-emerald-400" :
                                "border-slate-300 text-slate-600 dark:border-slate-700 dark:text-slate-400"
                              }`}
                            >
                              {sig.severity}
                            </Badge>
                          </div>
                          <div className="text-[11px] text-slate-500 dark:text-slate-400">
                            Category: <span className="font-medium text-slate-700 dark:text-slate-300">{sig.category}</span>
                          </div>
                          <p className="text-[11px] text-slate-600 dark:text-slate-300 leading-relaxed">
                            {sig.description}
                          </p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Evidence / Observations */}
                {scanResult.evidence && scanResult.evidence.length > 0 && (
                  <div className="mt-3 bg-white/40 dark:bg-slate-950/40 p-3 rounded-xl border border-slate-200 dark:border-slate-800/80 text-xs space-y-1">
                    <p className="font-semibold uppercase tracking-wider text-[10px] text-slate-500 dark:text-slate-400">
                      Evaluated Forensic Evidence:
                    </p>
                    <ul className="space-y-1 text-slate-700 dark:text-slate-300">
                      {scanResult.evidence.map((item, idx) => (
                        <li key={idx} className="flex items-start gap-1.5">
                          <span className="text-indigo-500 font-bold">•</span>
                          <span>{item}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )
          })()}
        </div>
      )}
    </div>
  )
}
