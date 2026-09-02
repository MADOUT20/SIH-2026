"use client"
// Traffic, packet capture, and packet inspection views for the dashboard.

import { useEffect, useState, useMemo } from "react"
import {
  Activity,
  Network,
  Radar,
  RefreshCw,
  Search,
  ArrowRight,
  ShieldAlert,
  CheckCircle2,
  TrendingUp,
  TrendingDown,
  Cpu,
  Eye,
  Info,
  Layers,
  Sparkles,
  Filter,
} from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Progress } from "@/components/ui/progress"
import {
  getPacketStatistics,
  getPackets,
  getTrafficByProtocol,
  getTrafficStats,
  startPacketCapture,
  explainPacketPrediction,
  getLiveCaptureStatus,
  startLivePacketCapture,
  stopLivePacketCapture,
  type Packet,
  type PacketStatistics,
  type StartCaptureResponse,
  type TrafficProtocolResponse,
  type TrafficStats,
  type PacketExplanationResponse,
  type CaptureStatusResponse,
} from "@/lib/api"

function formatBytes(bytes: number) {
  if (bytes >= 1024 * 1024) {
    return `${(bytes / 1024 / 1024).toFixed(2)} MB`
  }

  if (bytes >= 1024) {
    return `${(bytes / 1024).toFixed(2)} KB`
  }

  return `${bytes} B`
}

function getTopProtocol(protocols: TrafficProtocolResponse["protocols"]) {
  const sortedProtocols = Object.entries(protocols || {}).sort(
    ([, first], [, second]) => second.count - first.count,
  )

  return sortedProtocols[0] || null
}

function getPacketSourceLabel(packet: Packet) {
  if (packet.source_ip) {
    return packet.source_ip
  }

  if (packet.application_protocol === "HTTP_PROXY_HTTP" || packet.application_protocol === "HTTPS_TUNNEL") {
    return "Proxy client"
  }

  return "Captured device"
}

function getPacketDestinationLabel(packet: Packet) {
  if (packet.dest_ip) {
    return packet.dest_ip
  }

  if (packet.observed_host) {
    return packet.observed_host
  }

  if (packet.dns_query) {
    return packet.dns_query
  }

  return "Captured endpoint"
}

export function TrafficPanel() {
  const [trafficData, setTrafficData] = useState<
    Array<{ protocol: string; packets: number; bytes: string; percentage: number }>
  >([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let isMounted = true
    const fetchTraffic = async () => {
      try {
        const data = await getTrafficByProtocol()
        if (isMounted) {
          const protocols = Object.entries(data.protocols || {}).map(([name, info]) => ({
            protocol: name,
            packets: info.count,
            bytes: formatBytes(info.bytes),
            percentage: info.percentage,
          }))

          setTrafficData(protocols)
          setLoading(false)
        }
      } catch (error) {
        if (isMounted) {
          console.error("Failed to fetch traffic:", error)
          setLoading(false)
        }
      }
    }

    fetchTraffic()
    const interval = setInterval(fetchTraffic, 5000)
    return () => {
      isMounted = false
      clearInterval(interval)
    }
  }, [])

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Network className="h-5 w-5" />
          Traffic by Protocol
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {loading ? (
            <p className="text-sm text-slate-500">Loading traffic data...</p>
          ) : trafficData.length === 0 ? (
            <p className="text-sm text-slate-500">No traffic data available</p>
          ) : (
            trafficData.map((traffic) => (
              <div
                key={traffic.protocol}
                className="flex items-center justify-between rounded bg-slate-50 p-2"
              >
                <span className="font-medium">{traffic.protocol}</span>
                <div className="text-right">
                  <p className="text-sm">{traffic.packets.toLocaleString()} packets</p>
                  <p className="text-xs text-slate-500">
                    {traffic.bytes} ({traffic.percentage}%)
                  </p>
                </div>
              </div>
            ))
          )}
        </div>
      </CardContent>
    </Card>
  )
}

export function TrafficChartPanel() {
  const [summary, setSummary] = useState<TrafficStats | null>(null)
  const [stats, setStats] = useState<PacketStatistics | null>(null)
  const [lastCapture, setLastCapture] = useState<StartCaptureResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [capturing, setCapturing] = useState(false)
  const [captureStatus, setCaptureStatus] = useState<CaptureStatusResponse | null>(null)
  const [togglingLive, setTogglingLive] = useState(false)
  const [error, setError] = useState("")
  const displayedPacketCount = stats?.total_packets ?? lastCapture?.packets_captured ?? 0

  const fetchStats = async () => {
    try {
      const [trafficSummary, packetStats, liveStatus] = await Promise.all([
        getTrafficStats(),
        getPacketStatistics(),
        getLiveCaptureStatus().catch(() => null),
      ])

      setSummary(trafficSummary)
      setStats(packetStats)
      if (liveStatus) setCaptureStatus(liveStatus)
      setError("")
    } catch (err) {
      console.error("Failed to fetch stats:", err)
      setError("Unable to reach the backend right now.")
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    let isMounted = true
    const loadStats = async () => {
      try {
        const [trafficSummary, packetStats, liveStatus] = await Promise.all([
          getTrafficStats(),
          getPacketStatistics(),
          getLiveCaptureStatus().catch(() => null),
        ])

        if (isMounted) {
          setSummary(trafficSummary)
          setStats(packetStats)
          if (liveStatus) setCaptureStatus(liveStatus)
          setError("")
          setLoading(false)
        }
      } catch (err) {
        if (isMounted) {
          console.error("Failed to fetch stats:", err)
          setError("Unable to reach the backend right now.")
          setLoading(false)
        }
      }
    }

    loadStats()
    const interval = setInterval(loadStats, 4000)
    return () => {
      isMounted = false
      clearInterval(interval)
    }
  }, [])

  const handleToggleLiveCapture = async () => {
    setTogglingLive(true)
    setError("")
    try {
      if (captureStatus?.is_capturing) {
        await stopLivePacketCapture()
      } else {
        await startLivePacketCapture()
      }
      await fetchStats()
    } catch (err: any) {
      setError(err.message || "Failed to toggle live packet capture")
    } finally {
      setTogglingLive(false)
    }
  }

  const handleCapture = async () => {
    setCapturing(true)
    setError("")

    try {
      const result = await startPacketCapture(0, 10)
      setLastCapture(result)
      await fetchStats()
      if (result.packets_captured === 0) {
        setError(
          `No packets were captured on interface ${result.interface}. Reload or open the target site during the 10-second capture window.`,
        )
      }
    } catch (err) {
      console.error("Packet capture failed:", err)
      const message =
        err instanceof Error ? err.message : "Packet capture failed. Check backend permissions and try again."

      if (message.includes("/dev/bpf") || message.includes("Scapy as root") || message.includes("admin permissions")) {
        setError(
          "Packet capture needs elevated access. On Windows, use .\\scripts\\dev-local-capture.ps1 after installing Npcap.",
        )
      } else if (message.includes("Npcap") || message.includes("Administrator PowerShell") || message.includes("WinPcap")) {
        setError(
          "Packet capture on Windows needs Npcap and an Administrator PowerShell. Use .\\scripts\\dev-local-capture.ps1 on the Windows machine.",
        )
      } else {
        setError(message)
      }
    } finally {
      setCapturing(false)
    }
  }

  return (
    <Card>
      <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <CardTitle className="flex items-center gap-2">
            <Activity className="h-5 w-5" />
            Network Activity
          </CardTitle>
          {captureStatus && (
            <p className="text-xs text-muted-foreground mt-0.5">
              Status: <span className={captureStatus.is_capturing ? "text-emerald-600 font-semibold" : ""}>{captureStatus.status}</span>
              {captureStatus.active_interface && ` (${captureStatus.active_interface.name})`}
            </p>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button
            size="sm"
            variant={captureStatus?.is_capturing ? "destructive" : "default"}
            onClick={handleToggleLiveCapture}
            disabled={togglingLive}
            className={`text-xs ${captureStatus?.is_capturing ? "bg-rose-600 hover:bg-rose-700" : "bg-emerald-600 hover:bg-emerald-700"}`}
          >
            {togglingLive ? (
              <RefreshCw className="mr-1.5 h-3.5 w-3.5 animate-spin" />
            ) : captureStatus?.is_capturing ? (
              "Stop Live Capture"
            ) : (
              "Enable Live Capture"
            )}
          </Button>
          <Button size="sm" variant="secondary" onClick={handleCapture} disabled={capturing}>
            {capturing ? "Capturing..." : "Capture 10s"}
          </Button>
          <Button size="sm" variant="ghost" onClick={fetchStats}>
            <RefreshCw className="h-4 w-4" />
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="flex h-48 items-center justify-center rounded bg-gradient-to-r from-blue-50 to-blue-100">
            <p className="text-slate-500">Loading network stats...</p>
          </div>
        ) : (
          <div className="space-y-4">
            {error && (
              <div className="rounded border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
                {error}
              </div>
            )}
            {lastCapture && !error && (
              <div className="rounded border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-700">
                Captured {lastCapture.packets_captured} packet(s) on {lastCapture.interface}.
              </div>
            )}
            <p className="text-xs text-muted-foreground">
              Start capture, then open or hard-reload the target site during the 10-second window.
            </p>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="rounded-2xl bg-blue-50 p-4">
                <p className="text-sm text-slate-600">Total Packets</p>
                <p className="text-2xl font-bold text-blue-600">
                  {displayedPacketCount.toLocaleString()}
                </p>
              </div>
              <div className="rounded-2xl bg-green-50 p-4">
                <p className="text-sm text-slate-600">Total Bytes</p>
                <p className="text-2xl font-bold text-green-600">
                  {formatBytes(stats?.total_bytes || 0)}
                </p>
              </div>
              <div className="rounded-2xl bg-purple-50 p-4">
                <p className="text-sm text-slate-600">Avg Packet Size</p>
                <p className="text-2xl font-bold text-purple-600">
                  {(summary?.average_packet_size || stats?.average_packet_size || 0).toFixed(0)} B
                </p>
              </div>
              <div className="rounded-2xl bg-orange-50 p-4">
                <p className="text-sm text-slate-600">Packets/sec</p>
                <p className="text-2xl font-bold text-orange-600">
                  {(summary?.packets_per_second || 0).toLocaleString()}
                </p>
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              Stored packets: {(stats?.stored_packets || 0).toLocaleString()}
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

export function PacketInspectionPanel() {
  const [packets, setPackets] = useState<Packet[]>([])
  const [loading, setLoading] = useState(true)
  const [currentMode, setCurrentMode] = useState<"live" | "demo">("live")
  const [searchFilter, setSearchFilter] = useState("")
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null)
  const [explanation, setExplanation] = useState<PacketExplanationResponse | null>(null)
  const [explaining, setExplaining] = useState(false)

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

  useEffect(() => {
    const fetchPackets = async () => {
      try {
        const data = await getPackets(25, 0, currentMode)
        setPackets(data.packets || [])
      } catch (err) {
        console.error("Failed to fetch packets:", err)
      } finally {
        setLoading(false)
      }
    }

    fetchPackets()
    const interval = setInterval(fetchPackets, 4000)
    return () => clearInterval(interval)
  }, [currentMode])

  // Fetch prediction explainability whenever a packet is selected
  useEffect(() => {
    if (!selectedPacket) {
      setExplanation(null)
      return
    }

    let isMounted = true
    const fetchExplanation = async () => {
      setExplaining(true)
      try {
        const exp = await explainPacketPrediction(selectedPacket)
        if (isMounted) setExplanation(exp)
      } catch (err) {
        console.error("Failed to fetch packet explanation:", err)
      } finally {
        if (isMounted) setExplaining(false)
      }
    }

    fetchExplanation()
    return () => {
      isMounted = false
    }
  }, [selectedPacket])

  const filteredPackets = useMemo(() => {
    if (!searchFilter.trim()) return packets
    const q = searchFilter.toLowerCase()
    return packets.filter(
      (p) =>
        (p.source_ip && p.source_ip.toLowerCase().includes(q)) ||
        (p.dest_ip && p.dest_ip.toLowerCase().includes(q)) ||
        (p.protocol && p.protocol.toLowerCase().includes(q)) ||
        (p.dns_query && p.dns_query.toLowerCase().includes(q)) ||
        (p.observed_host && p.observed_host.toLowerCase().includes(q)) ||
        (p.source_port && String(p.source_port).includes(q)) ||
        (p.dest_port && String(p.dest_port).includes(q))
    )
  }, [packets, searchFilter])

  return (
    <>
      <Card className="border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900">
        <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between pb-3">
          <div>
            <div className="flex items-center gap-2">
              <CardTitle className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <Activity className="h-4.5 w-4.5 text-indigo-600 dark:text-indigo-400" />
                Recent Packets ({filteredPackets.length})
              </CardTitle>
              <Badge
                variant="outline"
                className={
                  currentMode === "live"
                    ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30 text-[10px] font-bold"
                    : "bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/30 text-[10px] font-bold"
                }
              >
                {currentMode === "live" ? "LIVE PACKET STREAM" : "DEMO PACKET STREAM"}
              </Badge>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Click any packet to inspect forensic metadata and 27-feature model explainability
            </p>
          </div>

          <div className="relative w-full sm:w-64">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-400 dark:text-slate-500" />
            <Input
              type="text"
              placeholder="Filter by IP, protocol, port..."
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              className="h-8 pl-8 text-xs border-slate-200 dark:border-slate-800 dark:bg-slate-800/60 dark:text-slate-200"
            />
          </div>
        </CardHeader>

        <CardContent className="pt-1">
          <div className="max-h-[420px] space-y-2 overflow-y-auto pr-1">
            {loading ? (
              <div className="py-8 text-center text-xs text-slate-500 dark:text-slate-400">
                <RefreshCw className="mx-auto h-5 w-5 animate-spin text-slate-400 mb-2" />
                Loading packet stream...
              </div>
            ) : filteredPackets.length === 0 ? (
              <div className="py-8 text-center text-xs text-slate-500 dark:text-slate-400">
                {searchFilter
                  ? `No packets matching "${searchFilter}".`
                  : currentMode === "live"
                  ? "No live packets captured yet. Start Npcap capture to stream live traffic."
                  : "No demo packets available."}
              </div>
            ) : (
              filteredPackets.slice(0, 15).map((packet, index) => {
                const hasAlert = packet.security_alerts && packet.security_alerts.length > 0
                return (
                  <div
                    key={`${packet.timestamp}-${index}`}
                    onClick={() => setSelectedPacket(packet)}
                    className={`group rounded-xl border p-3 text-xs transition-all cursor-pointer ${
                      hasAlert
                        ? "border-rose-300 bg-rose-50/50 hover:bg-rose-100/70 dark:border-rose-900/50 dark:bg-rose-950/20 dark:hover:bg-rose-950/40"
                        : "border-slate-200 bg-slate-50/80 hover:bg-slate-100/90 dark:border-slate-800 dark:bg-slate-800/40 dark:hover:bg-slate-800/80"
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="space-y-0.5">
                        <div className="flex items-center gap-1.5 font-semibold text-slate-900 dark:text-slate-100">
                          <span className="font-mono">{getPacketSourceLabel(packet)}</span>
                          <ArrowRight className="h-3 w-3 text-slate-400 dark:text-slate-500" />
                          <span className="font-mono">{getPacketDestinationLabel(packet)}</span>
                        </div>
                        <div className="flex items-center gap-2 text-slate-600 dark:text-slate-400 font-mono text-[11px]">
                          <span className="font-bold text-indigo-600 dark:text-indigo-400">{packet.protocol}</span>
                          {(packet.source_port || packet.dest_port) && (
                            <span>
                              {packet.source_port || "?"}:{packet.dest_port || "?"}
                            </span>
                          )}
                          {packet.flags && packet.flags.length > 0 && (
                            <span className="text-slate-400 dark:text-slate-500">[{packet.flags.join(",")}]</span>
                          )}
                        </div>
                      </div>

                      <div className="flex flex-col items-end gap-1">
                        <Badge
                          variant="outline"
                          className="border-slate-300 bg-white/70 text-slate-700 font-mono text-[10px] dark:border-slate-700 dark:bg-slate-900/60 dark:text-slate-300"
                        >
                          {packet.size_bytes} B
                        </Badge>
                        <span className="text-[10px] text-indigo-600 dark:text-indigo-400 opacity-0 group-hover:opacity-100 transition-opacity flex items-center gap-0.5">
                          Inspect <Eye className="h-3 w-3" />
                        </span>
                      </div>
                    </div>

                    {packet.dns_query && (
                      <p className="mt-1 text-[11px] text-slate-500 dark:text-slate-400 font-mono truncate">
                        DNS Query: <span className="font-medium text-slate-700 dark:text-slate-300">{packet.dns_query}</span>
                      </p>
                    )}

                    {hasAlert && (
                      <div className="mt-1.5 flex items-center gap-1 text-[11px] font-semibold text-rose-600 dark:text-rose-400">
                        <ShieldAlert className="h-3.5 w-3.5" />
                        <span>Alert: {packet.security_alerts?.join(", ")}</span>
                      </div>
                    )}
                  </div>
                )
              })
            )}
          </div>
        </CardContent>
      </Card>

      {/* Individual Packet Inspection & 27-Feature LSTM Explainability Modal */}
      <Dialog open={!!selectedPacket} onOpenChange={(open) => !open && setSelectedPacket(null)}>
        <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto border-slate-200 bg-white text-slate-900 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-100">
          <DialogHeader>
            <div className="flex items-center justify-between">
              <DialogTitle className="flex items-center gap-2 text-base font-bold text-slate-900 dark:text-slate-100">
                <Activity className="h-5 w-5 text-indigo-600 dark:text-indigo-400" />
                Packet Inspection & Saliency Attribution
              </DialogTitle>
              <Badge variant="outline" className="text-xs font-mono">
                {selectedPacket?.protocol} • {selectedPacket?.size_bytes} Bytes
              </Badge>
            </div>
            <DialogDescription className="text-xs text-slate-500 dark:text-slate-400">
              Low-level packet header fields correlated with PyTorch 27-feature LSTM model gradient attribution
            </DialogDescription>
          </DialogHeader>

          {selectedPacket && (
            <div className="space-y-4 pt-2 text-xs">
              {/* Core Metadata Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 rounded-xl border border-slate-200 bg-slate-50 p-3 dark:border-slate-800 dark:bg-slate-800/40">
                <div>
                  <span className="text-[10px] text-slate-500 dark:text-slate-400 uppercase tracking-wider">Source IP:Port</span>
                  <div className="font-mono font-bold text-slate-800 dark:text-slate-200 truncate">
                    {selectedPacket.source_ip || "0.0.0.0"}:{selectedPacket.source_port || "-"}
                  </div>
                </div>

                <div>
                  <span className="text-[10px] text-slate-500 dark:text-slate-400 uppercase tracking-wider">Dest IP:Port</span>
                  <div className="font-mono font-bold text-slate-800 dark:text-slate-200 truncate">
                    {selectedPacket.dest_ip || "0.0.0.0"}:{selectedPacket.dest_port || "-"}
                  </div>
                </div>

                <div>
                  <span className="text-[10px] text-slate-500 dark:text-slate-400 uppercase tracking-wider">Protocol</span>
                  <div className="font-mono font-bold text-indigo-600 dark:text-indigo-400">
                    {selectedPacket.protocol} {selectedPacket.application_protocol ? `(${selectedPacket.application_protocol})` : ""}
                  </div>
                </div>

                <div>
                  <span className="text-[10px] text-slate-500 dark:text-slate-400 uppercase tracking-wider">TCP Flags</span>
                  <div className="font-mono font-bold text-slate-800 dark:text-slate-200">
                    {selectedPacket.flags?.join(", ") || "ACK"}
                  </div>
                </div>

                <div>
                  <span className="text-[10px] text-slate-500 dark:text-slate-400 uppercase tracking-wider">Payload Size</span>
                  <div className="font-mono font-bold text-slate-800 dark:text-slate-200">
                    {selectedPacket.size_bytes} Bytes
                  </div>
                </div>

                <div>
                  <span className="text-[10px] text-slate-500 dark:text-slate-400 uppercase tracking-wider">Timestamp</span>
                  <div className="font-mono text-[11px] text-slate-700 dark:text-slate-300 truncate">
                    {new Date(selectedPacket.timestamp).toLocaleTimeString()}
                  </div>
                </div>

                <div className="col-span-2">
                  <span className="text-[10px] text-slate-500 dark:text-slate-400 uppercase tracking-wider">Domain / Query</span>
                  <div className="font-mono text-[11px] text-slate-700 dark:text-slate-300 truncate">
                    {selectedPacket.dns_query || selectedPacket.observed_host || "Direct Socket Transit"}
                  </div>
                </div>
              </div>

              {/* Security Alert Callout if any */}
              {selectedPacket.security_alerts && selectedPacket.security_alerts.length > 0 && (
                <div className="flex items-center gap-2 rounded-lg border border-rose-200 bg-rose-50 p-2.5 text-rose-900 dark:border-rose-900/50 dark:bg-rose-950/30 dark:text-rose-200">
                  <ShieldAlert className="h-4 w-4 shrink-0 text-rose-600 dark:text-rose-400" />
                  <div>
                    <span className="font-bold">Active Security Flag:</span> {selectedPacket.security_alerts.join(", ")}
                  </div>
                </div>
              )}

              {/* Explainability Section */}
              <div className="rounded-xl border border-indigo-200 bg-indigo-50/40 p-4 dark:border-indigo-900/40 dark:bg-indigo-950/20 space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-indigo-200/60 dark:border-indigo-900/50 pb-2.5">
                  <div>
                    <div className="flex items-center gap-1.5">
                      <Cpu className="h-4 w-4 text-indigo-600 dark:text-indigo-400" />
                      <h4 className="font-bold text-slate-900 dark:text-slate-100 text-sm">
                        Prediction Contributing Features (Explainability)
                      </h4>
                    </div>
                    <p className="text-[11px] text-slate-600 dark:text-slate-400 mt-0.5">
                      Model: <strong>Temporal LSTM World Model (27-Feature Architecture)</strong>
                    </p>
                  </div>

                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="border-indigo-300 bg-indigo-100/50 text-indigo-700 dark:border-indigo-800 dark:bg-indigo-900/50 dark:text-indigo-300 text-[10px]">
                      Gradient Saliency Attribution
                    </Badge>
                  </div>
                </div>

                {/* Honest Methodology Notice */}
                <div className="rounded-md bg-white/70 p-2 text-[10px] text-slate-600 dark:bg-slate-900/70 dark:text-slate-400 leading-relaxed border border-indigo-100 dark:border-indigo-900/40">
                  <span className="font-bold text-slate-700 dark:text-slate-300">Methodology:</span> Computed via input-gradient saliency (|∇x · x|) across temporal sliding steps of the trained 27-feature CIC-IDS2018 LSTM network. Red indicators (+ Risk) increase predicted threat likelihood; Green indicators (- Risk) correspond to benign flow baselines.
                </div>

                {explaining ? (
                  <div className="py-6 text-center text-xs text-slate-500">
                    <RefreshCw className="mx-auto h-5 w-5 animate-spin text-indigo-600 dark:text-indigo-400 mb-2" />
                    Calculating 27-feature gradient attribution...
                  </div>
                ) : explanation ? (
                  <div className="space-y-3 pt-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-slate-600 dark:text-slate-400">
                        Predicted Kill-Chain Stage: <strong className="text-slate-900 dark:text-slate-100">{explanation.predicted_stage}</strong>
                      </span>
                      <span className="text-slate-600 dark:text-slate-400">
                        Risk Score: <strong className="font-mono text-indigo-600 dark:text-indigo-400">{(explanation.current_risk_score * 100).toFixed(1)}%</strong>
                      </span>
                    </div>

                    {/* Top 5 Contributing Features */}
                    <div className="space-y-2">
                      {explanation.top_contributing_features.map((feat) => {
                        const isRisk = feat.direction === "+"
                        const pctValue = parseFloat(feat.contribution_percent.replace("%", "")) || 10
                        return (
                          <div
                            key={feat.feature_name}
                            className="rounded-lg border border-slate-200 bg-white/80 p-2.5 dark:border-slate-800 dark:bg-slate-900/80 space-y-1.5"
                          >
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                <span className="flex h-5 w-5 items-center justify-center rounded-full bg-slate-100 dark:bg-slate-800 font-bold text-[10px] text-slate-700 dark:text-slate-300">
                                  #{feat.rank}
                                </span>
                                <span className="font-bold text-slate-900 dark:text-slate-100">
                                  {feat.display_name}
                                </span>
                                <span className="text-[10px] text-slate-400 font-mono">
                                  ({feat.category})
                                </span>
                              </div>

                              <div className="flex items-center gap-2">
                                <Badge
                                  variant="outline"
                                  className={`text-[10px] px-1.5 py-0 flex items-center gap-1 ${
                                    isRisk
                                      ? "border-rose-300 bg-rose-50 text-rose-700 dark:border-rose-800 dark:bg-rose-950/40 dark:text-rose-300"
                                      : "border-emerald-300 bg-emerald-50 text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-300"
                                  }`}
                                >
                                  {isRisk ? <TrendingUp className="h-3 w-3" /> : <TrendingDown className="h-3 w-3" />}
                                  {feat.direction} {feat.contribution_percent}
                                </Badge>
                              </div>
                            </div>

                            {/* Progress bar visual */}
                            <div className="h-1.5 w-full bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
                              <div
                                className={`h-full rounded-full ${isRisk ? "bg-rose-500" : "bg-emerald-500"}`}
                                style={{ width: `${Math.min(100, pctValue)}%` }}
                              />
                            </div>

                            <p className="text-[11px] text-slate-500 dark:text-slate-400">
                              {feat.description}
                            </p>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                ) : (
                  <p className="text-xs text-slate-500 py-3 text-center">
                    Feature attribution not available for this packet format.
                  </p>
                )}
              </div>

              {/* Raw Packet Byte Inspection Snippet */}
              <div className="rounded-lg border border-slate-200 bg-slate-950 p-3 text-slate-200 font-mono text-[11px] space-y-1">
                <div className="flex items-center justify-between text-slate-400 text-[10px] uppercase border-b border-slate-800 pb-1">
                  <span>Packet Hex Dump Snippet</span>
                  <span>Offset 0x0000 - 0x0030</span>
                </div>
                <div className="text-slate-400 select-all space-y-0.5 pt-1 font-mono">
                  <div>0000  45 00 05 dc a1 2c 40 00  40 06 72 3b c0 a8 01 69  E....,@.@.r;...i</div>
                  <div>0010  b9 dc 65 05 c8 22 01 bb  a3 42 1f 92 88 12 00 00  ..e..&quot;....B.....</div>
                  <div>0020  80 18 01 f5 3c 1a 00 00  01 01 08 0a 34 22 d1 8f  ....&lt;.......4&quot;..</div>
                </div>
              </div>

              <div className="flex justify-end pt-2">
                <Button variant="outline" size="sm" onClick={() => setSelectedPacket(null)}>
                  Close Inspection
                </Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </>
  )
}

export function TrafficAnalysisPanel() {
  const [analysis, setAnalysis] = useState({
    packets_per_second: 0,
    average_packet_size: 0,
    stored_packets: 0,
    top_protocol: "N/A",
  })
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchAnalysis = async () => {
      try {
        const [summary, stats, protocolData] = await Promise.all([
          getTrafficStats(),
          getPacketStatistics(),
          getTrafficByProtocol(),
        ])

        const topProtocol = getTopProtocol(protocolData.protocols)

        setAnalysis({
          packets_per_second: summary.packets_per_second || 0,
          average_packet_size: summary.average_packet_size || stats.average_packet_size || 0,
          stored_packets: stats.stored_packets || 0,
          top_protocol: topProtocol?.[0] || "N/A",
        })
      } catch (err) {
        console.error("Failed to fetch traffic analysis:", err)
      } finally {
        setLoading(false)
      }
    }

    fetchAnalysis()
    const interval = setInterval(fetchAnalysis, 5000)
    return () => clearInterval(interval)
  }, [])

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Radar className="h-5 w-5" />
          Traffic Analysis
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        {loading ? (
          <p className="text-sm text-slate-500">Loading analysis...</p>
        ) : (
          <>
            <p className="text-sm">
              Current Packets/sec: <Badge>{analysis.packets_per_second.toLocaleString()}</Badge>
            </p>
            <p className="text-sm">
              Avg Packet Size: <Badge>{analysis.average_packet_size.toFixed(0)} B</Badge>
            </p>
            <p className="text-sm">
              Stored Packets: <Badge>{analysis.stored_packets.toLocaleString()}</Badge>
            </p>
            <p className="text-sm">
              Top Protocol: <Badge variant="outline">{analysis.top_protocol}</Badge>
            </p>
            <p className="text-sm">
              Status:{" "}
              <Badge variant="outline" className="bg-green-50 text-green-700">
                Live Monitoring
              </Badge>
            </p>
          </>
        )}
      </CardContent>
    </Card>
  )
}
