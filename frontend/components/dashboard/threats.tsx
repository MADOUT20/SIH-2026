"use client"
// Threat-focused panels including watch, actions, devices, and blocked sites.

import { useState, useEffect } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog"
import { 
  AlertTriangle, 
  ChevronLeft, 
  ChevronRight, 
  MapPin, 
  RefreshCw, 
  Shield, 
  Smartphone, 
  Wifi, 
  Zap,
  Layers,
  ExternalLink,
  ShieldAlert,
  Info,
  CheckCircle2,
  Lock,
  Unlock,
} from "lucide-react"
import {
  clearBlockedSites,
  getBlockedSites,
  getProxyStatus,
  getThreats,
  respondToThreat,
  unblockSite,
  unlockThreat,
  Threat,
  type BlockedSite,
  type ProxyClient,
} from "@/lib/api"

const DASHBOARD_REFRESH_EVENT = "netguard:dashboard-refresh"

function emitDashboardRefresh() {
  if (typeof window !== "undefined") {
    window.dispatchEvent(new Event(DASHBOARD_REFRESH_EVENT))
  }
}

function getSeverityClass(severity: Threat["severity"]) {
  if (severity === "CRITICAL") return "bg-red-50 dark:bg-red-950/20 border-red-200 dark:border-red-900/50"
  if (severity === "HIGH") return "bg-orange-50 dark:bg-orange-950/20 border-orange-200 dark:border-orange-900/50"
  if (severity === "MEDIUM") return "bg-yellow-50 dark:bg-yellow-950/20 border-yellow-200 dark:border-yellow-900/50"
  return "bg-blue-50 dark:bg-blue-950/20 border-blue-200 dark:border-blue-900/50"
}

function formatStatus(status: string) {
  return status.replace(/_/g, " ").replace(/\b\w/g, (match) => match.toUpperCase())
}

function formatThreatType(type: string) {
  return type.replace(/_/g, " ").replace(/\b\w/g, (match) => match.toUpperCase())
}

function getSeverityRank(severity: Threat["severity"]) {
  if (severity === "CRITICAL") return 4
  if (severity === "HIGH") return 3
  if (severity === "MEDIUM") return 2
  return 1
}

function isPrivateNetworkAddress(value?: string) {
  if (!value) return false
  if (value.startsWith("10.") || value.startsWith("192.168.")) return true
  const octets = value.split(".")
  if (octets.length < 2 || octets[0] !== "172") return false
  const secondOctet = Number(octets[1])
  return Number.isFinite(secondOctet) && secondOctet >= 16 && secondOctet <= 31
}

function formatThreatSource(sourceIp: string) {
  if (isPrivateNetworkAddress(sourceIp)) {
    return `Local device ${sourceIp}`
  }
  return sourceIp
}

function ThreatInvestigationModal({
  threat,
  open,
  onOpenChange,
  onBlockAction
}: {
  threat: Threat | null
  open: boolean
  onOpenChange: (open: boolean) => void
  onBlockAction: (threatId: string) => void
}) {
  if (!threat) return null

  const isDemo = (threat as any).is_demo ?? true
  const originLabel = (threat as any).origin || (isDemo ? "DEMO / SEEDED DATA" : "LIVE CAPTURE DETECTION")
  const mitre: any = threat.mitre_mapping || {}

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl border bg-card p-6 shadow-xl max-h-[90vh] overflow-y-auto">
        <DialogHeader className="space-y-2 border-b pb-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Badge variant="outline" className={isDemo ? "bg-amber-500/10 text-amber-500 border-amber-500/30 font-bold" : "bg-emerald-500/10 text-emerald-500 border-emerald-500/30 font-bold"}>
                {originLabel}
              </Badge>
              <Badge className={threat.severity === "CRITICAL" ? "bg-red-600 text-white font-bold" : threat.severity === "HIGH" ? "bg-orange-600 text-white font-bold" : "bg-yellow-600 text-white font-bold"}>
                {threat.severity} SEVERITY
              </Badge>
            </div>
            <span className="text-xs text-muted-foreground font-mono">ID: {threat.id}</span>
          </div>

          <DialogTitle className="text-xl font-bold flex items-center gap-2 text-foreground">
            <ShieldAlert className="h-5 w-5 text-red-500" />
            Threat Forensics: {formatThreatType(threat.type)}
          </DialogTitle>
          <DialogDescription className="text-sm text-muted-foreground">
            Deep packet inspection investigation, MITRE ATT&CK kill-chain mapping, and recommended response playbooks.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-5 py-4">
          {/* Overview Metric Grid */}
          <div className="grid gap-3 sm:grid-cols-3 text-xs">
            <div className="rounded-lg bg-muted p-3">
              <span className="text-muted-foreground uppercase text-[10px] font-semibold">Source Device</span>
              <p className="font-semibold text-sm mt-0.5">{formatThreatSource(threat.source_ip)}</p>
            </div>
            <div className="rounded-lg bg-muted p-3">
              <span className="text-muted-foreground uppercase text-[10px] font-semibold">Target Host</span>
              <p className="font-semibold text-sm mt-0.5 truncate">{threat.destination_host || threat.destination_ip || "Unknown"}</p>
            </div>
            <div className="rounded-lg bg-muted p-3">
              <span className="text-muted-foreground uppercase text-[10px] font-semibold">Confidence Score</span>
              <p className="font-semibold text-sm mt-0.5 text-sky-500">{((threat.threat_score || 0.9) * 100).toFixed(0)}%</p>
            </div>
          </div>

          {/* MITRE Vector Detail Box */}
          <div className="rounded-xl border bg-purple-500/10 border-purple-500/30 p-4 space-y-2 text-xs">
            <div className="flex items-center justify-between">
              <span className="font-bold text-purple-400 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                <Layers className="h-4 w-4 text-purple-400" />
                MITRE ATT&CK Kill-Chain Mapping
              </span>
              <Badge className="bg-purple-600 text-white font-bold">{mitre.stage_label || threat.attack_stage || "Stage 4: Execution"}</Badge>
            </div>
            <div className="grid gap-2 sm:grid-cols-2 pt-1 text-muted-foreground">
              <div>
                <span className="font-medium text-foreground">Technique ID: </span>
                <span className="font-mono text-purple-400 font-bold">{mitre.technique_id || threat.technique_id || "T1204.002"}</span>
              </div>
              <div>
                <span className="font-medium text-foreground">Technique: </span>
                <span>{mitre.technique_name || threat.technique_name || "User Execution: Malicious File"}</span>
              </div>
              <div className="sm:col-span-2">
                <span className="font-medium text-foreground">Tactic: </span>
                <span>{mitre.tactic_name || "Execution"} ({mitre.tactic_id || "TA0002"})</span>
              </div>
            </div>
          </div>

          {/* Alert Description & Evidence */}
          <div className="space-y-2">
            <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">Detection Reason & Evidence</h4>
            <div className="rounded-lg bg-muted p-3 text-xs space-y-2">
              <p className="font-medium text-foreground">{threat.description}</p>
              {threat.evidence && threat.evidence.length > 0 && (
                <ul className="list-disc list-inside space-y-1 text-muted-foreground pt-1 border-t border-border">
                  {threat.evidence.map((ev, i) => (
                    <li key={i}>{ev}</li>
                  ))}
                </ul>
              )}
            </div>
          </div>

          {/* Recommended Mitigations */}
          <div className="space-y-2">
            <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">Recommended Incident Response Playbook</h4>
            <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs space-y-1">
              <p className="font-semibold text-amber-500">NetGuard Recommended Playbook Actions:</p>
              <ul className="list-disc list-inside space-y-1 text-muted-foreground">
                <li>Enforce NetGuard local proxy domain block for target <span className="font-mono font-semibold text-foreground">{threat.destination_host || threat.source_ip}</span>.</li>
                <li>Terminate active TCP socket stream from host <span className="font-mono font-semibold text-foreground">{threat.source_ip}</span>.</li>
                <li>Revoke active session tokens and review EDR process tree.</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Modal Actions */}
        <div className="flex flex-col sm:flex-row gap-3 justify-between pt-3 border-t">
          <Button
            variant="destructive"
            onClick={() => {
              onBlockAction(threat.id)
              onOpenChange(false)
            }}
            disabled={threat.status === "blocked"}
          >
            {threat.status === "blocked" ? "Proxy Domain Blocked" : "Enforce Proxy Domain Block"}
          </Button>

          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Close Investigation
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}

interface ThreatDetectionPanelProps {
  excludeLow?: boolean
}

export function ThreatDetectionPanel({ excludeLow = false }: ThreatDetectionPanelProps) {
  const [threats, setThreats] = useState<Threat[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")
  const [message, setMessage] = useState("")
  const [activeIndex, setActiveIndex] = useState(0)
  const [investigatingThreat, setInvestigatingThreat] = useState<Threat | null>(null)
  const [modalOpen, setModalOpen] = useState(false)
  const [currentMode, setCurrentMode] = useState<"live" | "demo">("live")
  const [statusFilter, setStatusFilter] = useState<string>("all")

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

  const fetchThreats = async () => {
    try {
      setLoading(true)
      const data = await getThreats(statusFilter, undefined, currentMode)
      setThreats((data.threats || []).filter((threat) => threat.status !== "ignored"))
      setError("")
    } catch (err: any) {
      console.error("Failed to fetch threats:", err)
      setError("Failed to load threats")
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    let isMounted = true
    const load = async () => {
      try {
        const data = await getThreats(statusFilter, undefined, currentMode)
        if (isMounted) {
          setThreats((data.threats || []).filter((threat) => threat.status !== "ignored"))
          setError("")
          setLoading(false)
        }
      } catch (err: any) {
        if (isMounted) {
          console.error("Failed to fetch threats:", err)
          setError("Failed to load threats")
          setLoading(false)
        }
      }
    }

    load()
    const interval = setInterval(load, 5000)
    const handleRefresh = () => load()
    window.addEventListener(DASHBOARD_REFRESH_EVENT, handleRefresh)

    return () => {
      isMounted = false
      clearInterval(interval)
      window.removeEventListener(DASHBOARD_REFRESH_EVENT, handleRefresh)
    }
  }, [currentMode, statusFilter])

  const handleThreatAction = async (threatId: string, action: string) => {
    try {
      const result = await respondToThreat(threatId, action)
      setMessage(result.message || `Threat ${action.toLowerCase()} completed`)
      emitDashboardRefresh()
      await fetchThreats()
    } catch (err: any) {
      setMessage(err?.message || "Failed to respond to threat")
    }
  }

  const handleOpenInvestigate = (threat: Threat) => {
    setInvestigatingThreat(threat)
    setModalOpen(true)
    handleThreatAction(threat.id, "INVESTIGATE")
  }

  const visibleThreats = threats
    .filter((threat) => !excludeLow || threat.severity !== "LOW")
    .sort((left, right) => {
      const severityDifference = getSeverityRank(right.severity) - getSeverityRank(left.severity)
      if (severityDifference !== 0) {
        return severityDifference
      }
      return new Date(right.timestamp).getTime() - new Date(left.timestamp).getTime()
    })

  const safeActiveIndex = visibleThreats.length > 0
    ? Math.min(activeIndex, visibleThreats.length - 1)
    : 0
  const activeThreat = visibleThreats[safeActiveIndex] ?? null

  if (loading && threats.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-red-500" />
            Threats Detected
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-slate-500">Loading threats...</p>
        </CardContent>
      </Card>
    )
  }

  return (
    <>
      <Card>
        <CardHeader className="flex flex-row items-center justify-between pb-2">
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-red-500" />
            Threat Watch ({visibleThreats.length})
          </CardTitle>
          <div className="flex items-center gap-1.5">
            <div className="flex rounded-lg border border-slate-200 bg-slate-50 p-0.5 text-xs dark:border-slate-800 dark:bg-slate-900">
              {(["all", "active", "blocked", "resolved"] as const).map((s) => (
                <button
                  key={s}
                  onClick={() => setStatusFilter(s)}
                  className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${
                    statusFilter === s
                      ? "bg-white text-slate-900 shadow-sm dark:bg-slate-800 dark:text-slate-100"
                      : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100"
                  }`}
                >
                  {s.charAt(0).toUpperCase() + s.slice(1)}
                </button>
              ))}
            </div>
            <Button size="sm" variant="ghost" onClick={fetchThreats} className="h-7 w-7 p-0">
              <RefreshCw className="w-3.5 h-3.5" />
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          {error && <div className="text-red-500 text-sm">{error}</div>}
          {message && <div className="text-xs bg-muted p-2 rounded text-slate-600 font-medium">{message}</div>}

          {visibleThreats.length === 0 || !activeThreat ? (
            <div className="p-4 bg-emerald-500/10 border border-emerald-500/30 rounded-xl text-center space-y-1">
              <div className="flex items-center justify-center gap-2">
                <Badge variant="outline" className={currentMode === "live" ? "bg-emerald-500/10 text-emerald-500 border-emerald-500/30 text-[10px] font-bold" : "bg-amber-500/10 text-amber-500 border-amber-500/30 text-[10px] font-bold"}>
                  {currentMode === "live" ? "LIVE CAPTURE DETECTION" : "DEMO / SEEDED DATA"}
                </Badge>
              </div>
              <p className="text-sm font-semibold text-emerald-600 dark:text-emerald-400">
                {currentMode === "live" ? "No Live Threats Detected" : "No Demo Threats Loaded"}
              </p>
              <p className="text-xs text-muted-foreground">
                {currentMode === "live"
                  ? "Monitored Npcap network traffic is clean. Zero anomalous flows detected."
                  : "Switch to LIVE MODE or click refresh to load demo attack scenarios."}
              </p>
            </div>
          ) : (
            <>
              <div className="flex items-center justify-between gap-3">
                <p className="text-xs text-slate-500">
                  Threat {safeActiveIndex + 1} of {visibleThreats.length}
                </p>
                {visibleThreats.length > 1 && (
                  <div className="flex items-center gap-1">
                    <Button
                      size="icon"
                      variant="outline"
                      className="h-8 w-8"
                      onClick={() => setActiveIndex((currentIndex) => Math.max(0, currentIndex - 1))}
                      disabled={safeActiveIndex === 0}
                    >
                      <ChevronLeft className="h-4 w-4" />
                      <span className="sr-only">Previous threat</span>
                    </Button>
                    <Button
                      size="icon"
                      variant="outline"
                      className="h-8 w-8"
                      onClick={() => setActiveIndex((currentIndex) => Math.min(visibleThreats.length - 1, currentIndex + 1))}
                      disabled={safeActiveIndex === visibleThreats.length - 1}
                    >
                      <ChevronRight className="h-4 w-4" />
                      <span className="sr-only">Next threat</span>
                    </Button>
                  </div>
                )}
              </div>
              <div
                key={activeThreat.id}
                className={`rounded-2xl border p-4 shadow-sm ${getSeverityClass(activeThreat.severity)}`}
              >
                {/* Threat Header & Data Origin Badge */}
                <div className="mb-3 flex flex-col gap-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <Badge variant="outline" className={(activeThreat as any).is_demo ?? true ? "bg-amber-500/10 text-amber-500 border-amber-500/30 text-[10px] font-bold" : "bg-emerald-500/10 text-emerald-500 border-emerald-500/30 text-[10px] font-bold"}>
                      {(activeThreat as any).origin || ((activeThreat as any).is_demo ?? true ? "DEMO / SEEDED DATA" : "LIVE CAPTURE DETECTION")}
                    </Badge>

                    <div className="flex items-center gap-1.5">
                      <Badge
                        variant={activeThreat.severity === "CRITICAL" ? "destructive" : "default"}
                        className={
                          activeThreat.severity === "HIGH"
                            ? "bg-orange-600"
                            : activeThreat.severity === "MEDIUM"
                              ? "bg-yellow-600"
                              : "bg-blue-600"
                        }
                      >
                        {activeThreat.severity}
                      </Badge>
                      <Badge variant="outline">{formatStatus(activeThreat.status)}</Badge>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <p className="text-sm font-semibold text-slate-900 dark:text-slate-100">{formatThreatType(activeThreat.type)}</p>
                    {activeThreat.attack_stage || activeThreat.mitre_mapping?.stage_label ? (
                      <Badge className="bg-purple-600 hover:bg-purple-700 text-[10px] text-white font-bold px-2 py-0.5 flex items-center gap-1">
                        <Layers className="w-3 h-3" />
                        {activeThreat.attack_stage || activeThreat.mitre_mapping?.stage_label}
                      </Badge>
                    ) : null}
                  </div>
                </div>

                {/* MITRE ATT&CK & Threat Vector Info Strip */}
                {(activeThreat.mitre_mapping || activeThreat.technique_id) && (
                  <div className="mb-3 rounded-xl bg-purple-50 dark:bg-purple-950/30 border border-purple-200 dark:border-purple-900/50 p-2.5 flex flex-wrap items-center justify-between gap-2 text-xs">
                    <div className="flex items-center gap-1.5 font-medium text-purple-900 dark:text-purple-200">
                      <ShieldAlert className="w-3.5 h-3.5 text-purple-600" />
                      <span>MITRE Vector:</span>
                      <span className="font-mono font-bold text-indigo-700 dark:text-indigo-300">
                        {activeThreat.technique_id || activeThreat.mitre_mapping?.technique_id}
                      </span>
                      <span>-</span>
                      <span>{activeThreat.technique_name || activeThreat.mitre_mapping?.technique_name}</span>
                    </div>
                    {activeThreat.mitre_mapping?.reference_url && (
                      <a
                        href={activeThreat.mitre_mapping.reference_url}
                        target="_blank"
                        rel="noreferrer"
                        className="text-[11px] text-purple-600 hover:text-purple-800 dark:text-purple-400 font-medium flex items-center gap-0.5"
                      >
                        MITRE ATT&CK Info <ExternalLink className="w-3 h-3" />
                      </a>
                    )}
                  </div>
                )}

                <div className="mb-3 grid gap-2 sm:grid-cols-2">
                  <div className="rounded-xl bg-white/75 dark:bg-slate-900/75 px-3 py-2">
                    <p className="text-[11px] uppercase tracking-wide text-slate-500">Device</p>
                    <p className="mt-1 flex items-center gap-2 text-sm font-medium text-slate-900 dark:text-slate-100">
                      <Smartphone className="h-4 w-4 text-slate-500" />
                      {formatThreatSource(activeThreat.source_ip)}
                    </p>
                  </div>
                  <div className="rounded-xl bg-white/75 dark:bg-slate-900/75 px-3 py-2">
                    <p className="text-[11px] uppercase tracking-wide text-slate-500">Target</p>
                    <p className="mt-1 break-all text-sm font-medium text-slate-900 dark:text-slate-100">
                      {activeThreat.destination_host || activeThreat.destination_ip || "Unknown target"}
                    </p>
                  </div>
                  {activeThreat.destination_ip && (
                    <div className="rounded-xl bg-white/75 dark:bg-slate-900/75 px-3 py-2">
                      <p className="text-[11px] uppercase tracking-wide text-slate-500">Resolved IP</p>
                      <p className="mt-1 flex items-center gap-2 text-sm font-medium text-slate-900 dark:text-slate-100">
                        <MapPin className="h-4 w-4 text-slate-500" />
                        {activeThreat.destination_ip}
                        {activeThreat.destination_port ? `:${activeThreat.destination_port}` : ""}
                      </p>
                    </div>
                  )}
                  <div className="rounded-xl bg-white/75 dark:bg-slate-900/75 px-3 py-2">
                    <p className="text-[11px] uppercase tracking-wide text-slate-500">Confidence</p>
                    <p className="mt-1 text-sm font-medium text-slate-900 dark:text-slate-100">
                      {((activeThreat.threat_score || 0.9) * 100).toFixed(0)}%
                    </p>
                  </div>
                </div>

                <div className="rounded-xl bg-white/70 dark:bg-slate-900/70 px-3 py-3">
                  <p className="text-xs font-medium uppercase tracking-wide text-slate-500">Alert message</p>
                  <p className="mt-2 text-sm text-slate-700 dark:text-slate-300">{activeThreat.description}</p>
                </div>

                {activeThreat.evidence && activeThreat.evidence.length > 0 && (
                  <div className="mb-3 mt-3 space-y-1">
                    {activeThreat.evidence.slice(0, 2).map((item, index) => (
                      <p key={`${activeThreat.id}-evidence-${index}`} className="text-xs text-slate-500">
                        • {item}
                      </p>
                    ))}
                  </div>
                )}

                <div className="flex flex-col gap-2 sm:flex-row mt-4">
                  <Button
                    size="sm"
                    className="bg-red-600 text-xs hover:bg-red-700 sm:flex-1 text-white"
                    onClick={() => handleThreatAction(activeThreat.id, "BLOCK")}
                    disabled={activeThreat.status === "blocked"}
                  >
                    {activeThreat.status === "blocked" ? "Blocked" : "Block"}
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    className="text-xs sm:flex-1"
                    onClick={() => handleOpenInvestigate(activeThreat)}
                  >
                    Investigate
                  </Button>
                </div>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      {/* Threat Investigation Details Modal */}
      <ThreatInvestigationModal
        threat={investigatingThreat}
        open={modalOpen}
        onOpenChange={setModalOpen}
        onBlockAction={(id) => handleThreatAction(id, "BLOCK")}
      />
    </>
  )
}

export function ObservedDevicesCard() {
  const [clients, setClients] = useState<ProxyClient[]>([])
  const [proxyListening, setProxyListening] = useState(false)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let isMounted = true
    const fetchProxyDevices = async () => {
      try {
        const status = await getProxyStatus()
        if (isMounted) {
          setProxyListening(status.enabled && status.listening)
          setClients(status.clients || [])
          setLoading(false)
        }
      } catch (error) {
        if (isMounted) {
          console.error("Failed to fetch proxy status:", error)
          setLoading(false)
        }
      }
    }

    fetchProxyDevices()
    const interval = setInterval(fetchProxyDevices, 3000)
    return () => {
      isMounted = false
      clearInterval(interval)
    }
  }, [])

  const hasActiveClient = clients.length > 0
  const activeClientCount = clients.length

  return (
    <Card className="border-border bg-card">
      <CardHeader className="flex flex-row items-center justify-between gap-3">
        <CardTitle className="flex items-center gap-2">
          <Wifi className="h-5 w-5" />
          Observed Devices
        </CardTitle>
        <Badge variant="outline">{activeClientCount} live</Badge>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="rounded-2xl bg-slate-50 dark:bg-slate-900/50 p-4">
          <div className="flex items-center justify-between gap-3">
            <div>
              <p className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                {hasActiveClient
                  ? `${activeClientCount} device${activeClientCount === 1 ? "" : "s"} currently online`
                  : proxyListening
                    ? "Waiting for phone traffic"
                    : "Phone proxy is offline"}
              </p>
              <p className="text-xs text-slate-500">
                {hasActiveClient
                  ? "These devices sent traffic through the monitored proxy within the last 15 seconds."
                  : proxyListening
                    ? "A device is marked live only when traffic is seen in the last 15 seconds."
                    : "Start capture mode to watch phone traffic."}
              </p>
            </div>
            <Badge
              variant={hasActiveClient ? "default" : "outline"}
              className={hasActiveClient ? "bg-emerald-600" : proxyListening ? "bg-amber-600 text-white" : ""}
            >
              {hasActiveClient ? "LIVE" : proxyListening ? "IDLE" : "OFF"}
            </Badge>
          </div>
        </div>

        {loading ? (
          <p className="text-sm text-slate-500">Loading observed devices...</p>
        ) : clients.length === 0 ? (
          <div className="rounded-xl border border-dashed p-4 text-center text-xs text-slate-500">
            No live proxy devices connected. Start capturing traffic to populate.
          </div>
        ) : (
          <div className="space-y-2">
            {clients.map((client) => (
              <div key={client.ip} className="flex items-center justify-between rounded-xl border bg-card p-3 text-xs">
                <div className="flex items-center gap-2">
                  <Smartphone className="h-4 w-4 text-slate-500" />
                  <span className="font-medium">{client.ip}</span>
                </div>
                <span className="text-muted-foreground">{client.bytes_transferred || 0} bytes</span>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

export function BlockedSitesCard() {
  const [blockedSites, setBlockedSites] = useState<BlockedSite[]>([])
  const [loading, setLoading] = useState(true)
  const [actionMessage, setActionMessage] = useState<string | null>(null)
  const [unlockingKey, setUnlockingKey] = useState<string | null>(null)
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

  const fetchBlocked = async () => {
    try {
      const data = await getBlockedSites(currentMode)
      setBlockedSites(data.blocked_sites || [])
    } catch (err) {
      console.error("Failed to fetch blocked sites:", err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchBlocked()
    const interval = setInterval(fetchBlocked, 4000)
    const handleRefresh = () => fetchBlocked()
    window.addEventListener(DASHBOARD_REFRESH_EVENT, handleRefresh)
    return () => {
      clearInterval(interval)
      window.removeEventListener(DASHBOARD_REFRESH_EVENT, handleRefresh)
    }
  }, [currentMode])

  const handleUnlockThreat = async (site: BlockedSite) => {
    const key = site.threat_id || site.domain
    setUnlockingKey(key)
    setActionMessage(null)
    try {
      if (site.threat_id) {
        const res = await unlockThreat(site.threat_id)
        setActionMessage(`Threat unlocked: Active firewall/proxy block removed for ${site.domain || site.threat_id}.`)
      } else {
        await unblockSite(site.domain)
        setActionMessage(`Website ${site.domain} unblocked successfully.`)
      }
      await fetchBlocked()
      emitDashboardRefresh()
    } catch (err: any) {
      console.error("Failed to unlock threat:", err)
      setActionMessage(`Unlock failed: ${err.message || "Server error"}`)
    } finally {
      setUnlockingKey(null)
    }
  }

  const handleClearAll = async () => {
    try {
      await clearBlockedSites()
      setActionMessage("All active domain firewall block rules cleared.")
      fetchBlocked()
      emitDashboardRefresh()
    } catch (err: any) {
      console.error("Failed to clear blocked sites:", err)
    }
  }

  return (
    <Card className="border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900">
      <CardHeader className="flex flex-row items-center justify-between pb-3">
        <div>
          <div className="flex items-center gap-2">
            <CardTitle className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-purple-600 dark:text-purple-400" />
              Blocked Threats & Domains ({blockedSites.length})
            </CardTitle>
            <Badge
              variant="outline"
              className={currentMode === "live" ? "border-emerald-300 text-emerald-600 dark:border-emerald-800 dark:text-emerald-400 text-[10px]" : "border-amber-300 text-amber-600 dark:border-amber-800 dark:text-amber-400 text-[10px]"}
            >
              {currentMode === "live" ? "LIVE RULES" : "DEMO RULES"}
            </Badge>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Active firewall & proxy blocking rules enforcing zero-trust containment
          </p>
        </div>
        {blockedSites.length > 0 && (
          <Button
            size="sm"
            variant="outline"
            onClick={handleClearAll}
            className="text-xs h-8 border-slate-200 text-slate-700 hover:bg-slate-100 dark:border-slate-800 dark:text-slate-300 dark:hover:bg-slate-800"
          >
            Clear All Blocks
          </Button>
        )}
      </CardHeader>
      <CardContent className="space-y-3">
        {actionMessage && (
          <div className="flex items-center gap-2 p-2.5 rounded-lg border border-indigo-200 bg-indigo-50/70 text-xs text-indigo-900 dark:border-indigo-900/50 dark:bg-indigo-950/30 dark:text-indigo-200">
            <CheckCircle2 className="h-4 w-4 shrink-0 text-indigo-600 dark:text-indigo-400" />
            <span>{actionMessage}</span>
          </div>
        )}

        {loading ? (
          <p className="text-xs text-slate-500 dark:text-slate-400 py-3 text-center">Loading blocked threats...</p>
        ) : blockedSites.length === 0 ? (
          <div className="rounded-xl border border-dashed border-slate-200 p-6 text-center text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400">
            <Shield className="mx-auto h-8 w-8 text-slate-400 mb-2" />
            <p className="font-semibold text-slate-700 dark:text-slate-300">No Active Block Rules</p>
            <p className="mt-1">
              {currentMode === "live"
                ? "No domains or endpoints are currently blocked in live mode."
                : "No demo attack endpoints currently blocked. Enforce a block on any active threat to see it here."}
            </p>
          </div>
        ) : (
          <div className="space-y-2.5 max-h-[340px] overflow-y-auto">
            {blockedSites.map((site, index) => {
              const key = site.threat_id || site.domain || `blocked-${index}`
              const isUnlocking = unlockingKey === (site.threat_id || site.domain)
              return (
                <div
                  key={key}
                  className="rounded-lg border border-slate-200 bg-slate-50/80 p-3 text-xs transition-colors dark:border-slate-800 dark:bg-slate-800/40"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono font-bold text-slate-900 dark:text-slate-100">
                          {site.domain}
                        </span>
                        <Badge
                          variant="outline"
                          className="border-purple-300 bg-purple-500/10 text-purple-700 dark:border-purple-800 dark:text-purple-300 text-[10px]"
                        >
                          BLOCKED
                        </Badge>
                        {site.severity && (
                          <Badge
                            variant="outline"
                            className={`text-[10px] ${
                              site.severity === "CRITICAL"
                                ? "border-rose-300 text-rose-600 dark:border-rose-800 dark:text-rose-400"
                                : "border-amber-300 text-amber-600 dark:border-amber-800 dark:text-amber-400"
                            }`}
                          >
                            {site.severity}
                          </Badge>
                        )}
                      </div>

                      <div className="text-[11px] text-slate-600 dark:text-slate-400">
                        <span className="font-medium text-slate-700 dark:text-slate-300">Reason:</span> {site.threat_type || site.reason || "Active Threat Detection"}
                        {site.threat_id && (
                          <span className="ml-2 font-mono text-[10px] text-slate-500">ID: {site.threat_id}</span>
                        )}
                      </div>

                      {site.blocked_at && (
                        <div className="text-[10px] text-slate-500 dark:text-slate-400">
                          Blocked at: {new Date(site.blocked_at).toLocaleTimeString()} ({new Date(site.blocked_at).toLocaleDateString()})
                        </div>
                      )}
                    </div>

                    <Button
                      size="sm"
                      onClick={() => handleUnlockThreat(site)}
                      disabled={isUnlocking}
                      className="h-7 px-3 text-xs font-medium bg-indigo-600 hover:bg-indigo-700 text-white shrink-0 flex items-center gap-1.5"
                    >
                      <Unlock className="h-3 w-3" />
                      {isUnlocking ? "Unlocking..." : "Unlock"}
                    </Button>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

export function ThreatResponsePanel() {
  return null
}

export function OSProtection() {
  return null
}
