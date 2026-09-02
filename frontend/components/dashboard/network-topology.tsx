"use client"

import { useState, useEffect, useMemo, useCallback, useRef } from "react"
import {
  Network,
  Laptop,
  Server,
  Router,
  Globe,
  AlertTriangle,
  Skull,
  Shield,
  ShieldAlert,
  ArrowRight,
  Activity,
  RefreshCw,
  Filter,
  Eye,
  Radio,
  ExternalLink,
  Layers,
  ChevronRight,
  Sparkles,
  Info,
  CheckCircle2,
  Play,
  Square,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Radar,
  Wifi,
  Lock,
  Cpu,
} from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  getNetworkTopology,
  getLiveCaptureStatus,
  startLivePacketCapture,
  stopLivePacketCapture,
  type TopologyNode,
  type TopologyLink,
  type NetworkTopologyResponse,
  type CaptureStatusResponse,
} from "@/lib/api"

interface NetworkTopologyProps {
  onNavigateToTraffic?: () => void
}

export function NetworkTopologyPanel({ onNavigateToTraffic }: NetworkTopologyProps) {
  const [mode, setMode] = useState<"live" | "demo">("live")
  const [topologyData, setTopologyData] = useState<NetworkTopologyResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null)
  const [selectedLink, setSelectedLink] = useState<TopologyLink | null>(null)
  const [roleFilter, setRoleFilter] = useState<string>("all")
  const [protocolFilter, setProtocolFilter] = useState<string>("all")
  const [viewMode, setViewMode] = useState<"visual" | "table">("visual")

  // Capture status & toggle state
  const [captureStatus, setCaptureStatus] = useState<CaptureStatusResponse | null>(null)
  const [togglingCapture, setTogglingCapture] = useState(false)
  const [captureActionError, setCaptureActionError] = useState<string | null>(null)

  // Zoom / Pan scale
  const [zoomLevel, setZoomLevel] = useState<number>(1.0)

  // Persistent coordinate store: nodes NEVER jump or change positions between updates
  const persistentPositionsRef = useRef<Map<string, { x: number; y: number }>>(new Map())
  // Track allocated tier slot counts: { tier0: count, tier1: count, ... }
  const tierSlotCountsRef = useRef<{ [tier: number]: number }>({ 0: 0, 1: 0, 2: 0, 3: 0 })

  // Read app mode from local storage
  useEffect(() => {
    try {
      const storedMode = localStorage.getItem("netguard_app_mode")
      if (storedMode === "demo" || storedMode === "live") {
        setMode(storedMode)
      }
    } catch {
      // ignore
    }

    const handleModeChange = (e: any) => {
      if (e.detail?.mode) {
        setMode(e.detail.mode)
      }
    }
    window.addEventListener("netguard:mode-change", handleModeChange)
    return () => window.removeEventListener("netguard:mode-change", handleModeChange)
  }, [])

  // Poll capture status
  const fetchCaptureStatus = useCallback(async () => {
    try {
      const status = await getLiveCaptureStatus()
      setCaptureStatus(status)
    } catch {
      // ignore status polling errors
    }
  }, [])

  useEffect(() => {
    fetchCaptureStatus()
    const statusInterval = setInterval(fetchCaptureStatus, 3000)
    return () => clearInterval(statusInterval)
  }, [fetchCaptureStatus])

  // Fetch topology
  const fetchTopology = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await getNetworkTopology(mode)
      setTopologyData(data)
    } catch (err: any) {
      setError(err.message || "Failed to load network topology")
    } finally {
      setLoading(false)
    }
  }, [mode])

  useEffect(() => {
    fetchTopology()
    const interval = setInterval(fetchTopology, 5000)
    return () => clearInterval(interval)
  }, [fetchTopology])

  // Toggle live packet capture
  const handleToggleCapture = async () => {
    setTogglingCapture(true)
    setCaptureActionError(null)
    try {
      if (captureStatus?.is_capturing) {
        await stopLivePacketCapture()
      } else {
        await startLivePacketCapture()
      }
      await fetchCaptureStatus()
      await fetchTopology()
    } catch (err: any) {
      setCaptureActionError(err.message || "Failed to change capture state")
    } finally {
      setTogglingCapture(false)
    }
  }

  // Filtered nodes
  const filteredNodes = useMemo(() => {
    if (!topologyData?.nodes) return []
    return topologyData.nodes.filter((node) => {
      if (roleFilter !== "all") {
        if (roleFilter === "local" && !node.is_local) return false
        if (roleFilter === "threat" && node.status !== "compromised" && node.status !== "attacker" && node.threat_level !== "CRITICAL" && node.threat_level !== "HIGH") return false
        if (roleFilter === "servers" && node.role !== "server" && node.role !== "gateway" && node.role !== "dns") return false
      }
      if (protocolFilter !== "all" && !node.protocols.includes(protocolFilter)) {
        return false
      }
      return true
    })
  }, [topologyData?.nodes, roleFilter, protocolFilter])

  // Nodes lookup map
  const nodesMap = useMemo(() => {
    const map = new Map<string, TopologyNode>()
    topologyData?.nodes.forEach((n) => map.set(n.id, n))
    return map
  }, [topologyData?.nodes])

  // Reset layout positions when switching modes
  useEffect(() => {
    persistentPositionsRef.current.clear()
    tierSlotCountsRef.current = { 0: 0, 1: 0, 2: 0, 3: 0 }
  }, [mode])

  // Compute node coordinate positions for SVG layout with ZERO jumping
  const nodePositions = useMemo(() => {
    const positions = new Map<string, { x: number; y: number }>()
    const nodes = topologyData?.nodes || []
    if (nodes.length === 0) return positions

    const width = 960
    const height = 520

    if (mode === "demo") {
      // Fixed deterministic layout for 7-node demonstration attack topology
      // Left: External Threats -> Center: Gateways & DNS -> Right: Internal Workstations & Core DB
      const demoCoords: Record<string, { x: number; y: number }> = {
        "185.220.101.5": { x: 120, y: 220 }, // C2 External Threat (far left)
        "1.1.1.1": { x: 370, y: 110 },        // Cloudflare DNS (top center)
        "192.168.1.1": { x: 370, y: 270 },    // Gateway / Firewall (center)
        "192.168.1.45": { x: 620, y: 390 },   // Admin Workstation (bottom right)
        "192.168.1.105": { x: 620, y: 210 },  // Compromised Laptop (mid right)
        "192.168.1.10": { x: 840, y: 140 },   // Domain Controller (far right top)
        "192.168.1.200": { x: 840, y: 310 },  // Database Server (far right bottom)
      }

      nodes.forEach((n, idx) => {
        if (demoCoords[n.id]) {
          positions.set(n.id, demoCoords[n.id])
        } else {
          positions.set(n.id, {
            x: 200 + ((idx * 160) % 550),
            y: 120 + ((idx * 100) % 320),
          })
        }
      })
      return positions
    }

    // LIVE MODE: Stable Tier-Based Slot Placement
    // Tier 0 (x=130): Local Laptop / Workstation endpoints
    // Tier 1 (x=380): Default Gateway / Router / Firewall
    // Tier 2 (x=630): DNS Resolvers & Core Infrastructure
    // Tier 3 (x=850): External Web Servers / Cloud Services
    const tierX = [130, 380, 630, 850]
    const tierYBase = [120, 160, 130, 100]
    const tierYStep = [110, 120, 100, 85]

    nodes.forEach((node) => {
      // If position was already computed previously, REUSE IT EXACTLY
      if (persistentPositionsRef.current.has(node.id)) {
        positions.set(node.id, persistentPositionsRef.current.get(node.id)!)
        return
      }

      // Determine appropriate tier
      let tier = 3 // default external
      if (node.role === "workstation" || node.role === "localhost" || node.label.toLowerCase().includes("laptop")) {
        tier = 0
      } else if (node.role === "gateway" || node.role === "router") {
        tier = 1
      } else if (node.role === "dns" || node.ports?.includes(53)) {
        tier = 2
      } else if (node.is_local) {
        tier = 0
      }

      const slot = tierSlotCountsRef.current[tier] || 0
      tierSlotCountsRef.current[tier] = slot + 1

      // Compute coordinate
      const x = tierX[tier]
      const y = Math.min(height - 70, tierYBase[tier] + slot * tierYStep[tier])

      const coord = { x, y }
      persistentPositionsRef.current.set(node.id, coord)
      positions.set(node.id, coord)
    })

    return positions
  }, [topologyData?.nodes, mode])

  const getNodeIcon = (node: TopologyNode) => {
    switch (node.role) {
      case "router":
      case "gateway":
        return <Router className="h-5 w-5" />
      case "c2_server":
      case "adversary":
        return <Skull className="h-5 w-5 text-rose-500" />
      case "scanner":
        return <AlertTriangle className="h-5 w-5 text-amber-500" />
      case "server":
        return <Server className="h-5 w-5 text-sky-500" />
      case "dns":
        return <Globe className="h-5 w-5 text-cyan-400" />
      case "external":
        return <Globe className="h-5 w-5 text-indigo-400" />
      default:
        return <Laptop className="h-5 w-5 text-emerald-400" />
    }
  }

  const getNodeBadgeColor = (status: string) => {
    switch (status) {
      case "attacker":
      case "hostile":
        return "bg-rose-500/15 text-rose-600 border-rose-300 dark:bg-rose-950/40 dark:text-rose-300 dark:border-rose-800"
      case "compromised":
      case "threat_detected":
        return "bg-amber-500/15 text-amber-600 border-amber-300 dark:bg-amber-950/40 dark:text-amber-300 dark:border-amber-800"
      case "warning":
        return "bg-amber-500/15 text-amber-600 border-amber-300 dark:bg-amber-950/40 dark:text-amber-300 dark:border-amber-800"
      case "blocked":
        return "bg-purple-500/15 text-purple-600 border-purple-300 dark:bg-purple-950/40 dark:text-purple-300 dark:border-purple-800"
      default:
        return "bg-emerald-500/15 text-emerald-600 border-emerald-300 dark:bg-emerald-950/40 dark:text-emerald-300 dark:border-emerald-800"
    }
  }

  const isLiveCaptureActive = captureStatus?.is_capturing ?? false
  const hasLiveDevices = Boolean(topologyData && topologyData.nodes && topologyData.nodes.length > 0)

  return (
    <div className="space-y-6">
      {/* Top Banner & Control Bar */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-indigo-500/10 text-indigo-600 dark:bg-indigo-950/50 dark:text-indigo-400">
              <Network className="h-6 w-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
                  Device Connectivity & Network Map
                </h2>
                <Badge
                  variant="outline"
                  className={
                    mode === "live"
                      ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 font-bold text-[11px]"
                      : "border-indigo-500/40 bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 font-bold text-[11px]"
                  }
                >
                  {mode === "live" ? "LIVE NETWORK MAP" : "DEMO NETWORK MAP"}
                </Badge>
              </div>
              <p className="text-sm text-slate-600 dark:text-slate-400">
                Interactive topology of active endpoints, hardware gateways, and observed packet flows
              </p>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {/* Personal Proxy / Device Capture Control */}
          <div className="flex items-center rounded-lg border border-slate-200 bg-white p-1 shadow-sm dark:border-slate-800 dark:bg-slate-900">
            <div className="flex items-center gap-2 px-2.5 py-1">
              <div
                className={`h-2.5 w-2.5 rounded-full ${
                  isLiveCaptureActive
                    ? "bg-emerald-500 animate-pulse"
                    : captureStatus?.status_code === "PERMISSION_REQUIRED"
                    ? "bg-amber-500"
                    : captureStatus?.status_code === "NPCAP_MISSING"
                    ? "bg-rose-500"
                    : "bg-slate-400"
                }`}
              />
              <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                {isLiveCaptureActive
                  ? "LIVE CAPTURE ACTIVE"
                  : togglingCapture
                  ? "Starting..."
                  : captureStatus?.status || "Capture OFF"}
              </span>
            </div>

            <Button
              size="sm"
              variant={isLiveCaptureActive ? "destructive" : "default"}
              onClick={handleToggleCapture}
              disabled={togglingCapture}
              className={`h-7 px-3 text-xs font-medium ${
                isLiveCaptureActive
                  ? "bg-rose-600 hover:bg-rose-700 text-white"
                  : "bg-emerald-600 hover:bg-emerald-700 text-white"
              }`}
            >
              {togglingCapture ? (
                <RefreshCw className="mr-1.5 h-3.5 w-3.5 animate-spin" />
              ) : isLiveCaptureActive ? (
                <Square className="mr-1.5 h-3 w-3 fill-current" />
              ) : (
                <Play className="mr-1.5 h-3 w-3 fill-current" />
              )}
              {isLiveCaptureActive ? "Stop Capture" : "Enable Device Capture"}
            </Button>
          </div>

          {/* Mode Switcher */}
          <div className="flex items-center rounded-lg border border-slate-200 bg-slate-50 p-1 dark:border-slate-800 dark:bg-slate-900">
            <Button
              variant={mode === "live" ? "default" : "ghost"}
              size="sm"
              onClick={() => {
                setMode("live")
                localStorage.setItem("netguard_app_mode", "live")
                window.dispatchEvent(new CustomEvent("netguard:mode-change", { detail: { mode: "live" } }))
              }}
              className={`h-8 px-3 text-xs font-semibold ${
                mode === "live"
                  ? "bg-emerald-600 text-white hover:bg-emerald-700 dark:bg-emerald-600"
                  : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100"
              }`}
            >
              <Radio className="mr-1.5 h-3.5 w-3.5 animate-pulse text-white" />
              LIVE MODE
            </Button>
            <Button
              variant={mode === "demo" ? "default" : "ghost"}
              size="sm"
              onClick={() => {
                setMode("demo")
                localStorage.setItem("netguard_app_mode", "demo")
                window.dispatchEvent(new CustomEvent("netguard:mode-change", { detail: { mode: "demo" } }))
              }}
              className={`h-8 px-3 text-xs font-semibold ${
                mode === "demo"
                  ? "bg-indigo-600 text-white hover:bg-indigo-700 dark:bg-indigo-600"
                  : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100"
              }`}
            >
              <Sparkles className="mr-1.5 h-3.5 w-3.5 text-white" />
              DEMO MODE
            </Button>
          </div>

          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              fetchTopology()
              fetchCaptureStatus()
            }}
            disabled={loading}
            className="h-8 gap-1.5 border-slate-200 text-slate-700 hover:bg-slate-100 dark:border-slate-800 dark:text-slate-300 dark:hover:bg-slate-800"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </Button>

          <div className="flex items-center rounded-lg border border-slate-200 bg-white p-0.5 dark:border-slate-800 dark:bg-slate-900">
            <Button
              variant={viewMode === "visual" ? "secondary" : "ghost"}
              size="sm"
              onClick={() => setViewMode("visual")}
              className="h-8 px-2.5 text-xs"
            >
              Visual Map
            </Button>
            <Button
              variant={viewMode === "table" ? "secondary" : "ghost"}
              size="sm"
              onClick={() => setViewMode("table")}
              className="h-8 px-2.5 text-xs"
            >
              Table View
            </Button>
          </div>
        </div>
      </div>

      {/* Mode Status & Interface Diagnostic Pill Banner */}
      {mode === "demo" ? (
        <div className="flex items-start gap-3 rounded-xl border border-indigo-200 bg-indigo-50/70 p-3.5 text-indigo-950 dark:border-indigo-900/50 dark:bg-indigo-950/20 dark:text-indigo-200">
          <Sparkles className="h-5 w-5 shrink-0 text-indigo-600 dark:text-indigo-400 mt-0.5" />
          <div className="text-xs leading-relaxed">
            <span className="font-bold uppercase tracking-wider text-indigo-700 dark:text-indigo-300">DEMO NETWORK MAP ACTIVE:</span> Displaying stored deterministic enterprise attack scenario (External C2 ➔ Edge Firewall ➔ Compromised Internal Laptop ➔ Domain Controller & Core DB). These simulated endpoints allow testing forensic graph tracing without live traffic.
          </div>
        </div>
      ) : (
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 rounded-xl border border-emerald-200 bg-emerald-50/70 p-3.5 text-emerald-950 dark:border-emerald-900/50 dark:bg-emerald-950/20 dark:text-emerald-200">
          <div className="flex items-center gap-3">
            <CheckCircle2 className="h-5 w-5 shrink-0 text-emerald-600 dark:text-emerald-400" />
            <div className="text-xs leading-relaxed">
              <span className="font-bold uppercase tracking-wider text-emerald-700 dark:text-emerald-300">LIVE NETWORK MAP ACTIVE:</span> Inspecting real packets from this machine. Only actual observed network communication is rendered.
            </div>
          </div>
          {captureStatus?.active_interface && (
            <div className="flex items-center gap-2 text-[11px] font-mono text-emerald-800 dark:text-emerald-300 shrink-0">
              <Wifi className="h-3.5 w-3.5" />
              <span>
                Interface: {captureStatus.active_interface.name} ({captureStatus.active_interface.ips?.[0] || "Active"})
              </span>
            </div>
          )}
        </div>
      )}

      {captureActionError && (
        <div className="rounded-lg border border-rose-300 bg-rose-50 p-3 text-xs text-rose-800 dark:border-rose-900 dark:bg-rose-950/40 dark:text-rose-300 flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 shrink-0 text-rose-600" />
          <span>{captureActionError}</span>
        </div>
      )}

      {/* Metric Quick Stats */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Card className="border-slate-200 bg-white/80 shadow-sm dark:border-slate-800 dark:bg-slate-900/60">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-600 dark:text-slate-400">Observed Devices</span>
              <Laptop className="h-4 w-4 text-indigo-500" />
            </div>
            <div className="mt-2 text-2xl font-bold text-slate-900 dark:text-slate-100">
              {topologyData?.total_devices ?? 0}
            </div>
            <div className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
              {topologyData?.nodes.filter((n) => n.is_local).length ?? 0} Local / Internal Host(s)
            </div>
          </CardContent>
        </Card>

        <Card className="border-slate-200 bg-white/80 shadow-sm dark:border-slate-800 dark:bg-slate-900/60">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-600 dark:text-slate-400">Active Packet Links</span>
              <Activity className="h-4 w-4 text-emerald-500" />
            </div>
            <div className="mt-2 text-2xl font-bold text-slate-900 dark:text-slate-100">
              {topologyData?.links.length ?? 0}
            </div>
            <div className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
              Directional observed flows
            </div>
          </CardContent>
        </Card>

        <Card className="border-slate-200 bg-white/80 shadow-sm dark:border-slate-800 dark:bg-slate-900/60">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-600 dark:text-slate-400">Threat / Critical Nodes</span>
              <ShieldAlert className="h-4 w-4 text-rose-500" />
            </div>
            <div className="mt-2 text-2xl font-bold text-rose-600 dark:text-rose-400">
              {topologyData?.nodes.filter((n) => n.status === "compromised" || n.status === "attacker" || n.threat_level === "CRITICAL" || n.threat_level === "HIGH").length ?? 0}
            </div>
            <div className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
              {mode === "demo" ? "Attacker & Compromised Node" : "Zero active threats detected"}
            </div>
          </CardContent>
        </Card>

        <Card className="border-slate-200 bg-white/80 shadow-sm dark:border-slate-800 dark:bg-slate-900/60">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-600 dark:text-slate-400">Data Volume</span>
              <Radio className="h-4 w-4 text-sky-500" />
            </div>
            <div className="mt-2 text-2xl font-bold text-slate-900 dark:text-slate-100">
              {topologyData?.links.reduce((acc, l) => acc + (l.byte_count || 0), 0)
                ? (topologyData.links.reduce((acc, l) => acc + (l.byte_count || 0), 0) / 1024).toFixed(1) + " KB"
                : "0.0 KB"}
            </div>
            <div className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
              {topologyData?.links.reduce((acc, l) => acc + (l.packet_count || 0), 0) ?? 0} packets captured
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Filters & Search Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-200 bg-white p-3 dark:border-slate-800 dark:bg-slate-900">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-700 dark:text-slate-300">
            <Filter className="h-4 w-4 text-slate-500" />
            <span>Filter Devices:</span>
          </div>

          <Select value={roleFilter} onValueChange={setRoleFilter}>
            <SelectTrigger className="h-8 w-36 text-xs border-slate-200 dark:border-slate-800">
              <SelectValue placeholder="All Roles" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Roles</SelectItem>
              <SelectItem value="local">Local Hosts & Laptop</SelectItem>
              <SelectItem value="threat">Threats & Hostile</SelectItem>
              <SelectItem value="servers">Gateways & Servers</SelectItem>
            </SelectContent>
          </Select>

          <Select value={protocolFilter} onValueChange={setProtocolFilter}>
            <SelectTrigger className="h-8 w-36 text-xs border-slate-200 dark:border-slate-800">
              <SelectValue placeholder="All Protocols" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Protocols</SelectItem>
              <SelectItem value="TCP">TCP</SelectItem>
              <SelectItem value="UDP">UDP</SelectItem>
              <SelectItem value="DNS">DNS</SelectItem>
              <SelectItem value="ICMP">ICMP</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <div className="flex items-center gap-3 text-xs text-slate-500 dark:text-slate-400">
          <div className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-emerald-500"></span>
            <span>Host / Clean</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-indigo-500"></span>
            <span>Gateway / Router</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-cyan-400"></span>
            <span>DNS / Cloud</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-rose-500"></span>
            <span>Threat / Attacker</span>
          </div>
        </div>
      </div>

      {/* Main Visualization or Table View */}
      {viewMode === "visual" ? (
        <Card className="overflow-hidden border-slate-200 bg-gradient-to-b from-slate-900 to-slate-950 text-slate-100 shadow-xl dark:border-slate-800">
          <CardHeader className="border-b border-slate-800/80 bg-slate-950/60 p-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <CardTitle className="text-base text-slate-100 flex items-center gap-2">
                  <span>Interactive Network Visual Map</span>
                  <Badge variant="outline" className="border-indigo-500/30 text-indigo-300 text-[11px]">
                    {mode === "demo" ? "DEMO TOPOLOGY" : "LIVE CAPTURE"}
                  </Badge>
                </CardTitle>
                <CardDescription className="text-xs text-slate-400">
                  Click any node or link to view packet forensics and socket telemetry
                </CardDescription>
              </div>

              {/* Interactive Zoom and Pan Controls */}
              <div className="flex items-center gap-2">
                <div className="flex items-center rounded-lg border border-slate-800 bg-slate-900/90 p-0.5 text-xs text-slate-300">
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7 text-slate-300 hover:text-white hover:bg-slate-800"
                    onClick={() => setZoomLevel((z) => Math.min(1.5, z + 0.1))}
                    title="Zoom In"
                  >
                    <ZoomIn className="h-3.5 w-3.5" />
                  </Button>
                  <span className="px-1.5 text-[11px] font-mono">{Math.round(zoomLevel * 100)}%</span>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7 text-slate-300 hover:text-white hover:bg-slate-800"
                    onClick={() => setZoomLevel((z) => Math.max(0.7, z - 0.1))}
                    title="Zoom Out"
                  >
                    <ZoomOut className="h-3.5 w-3.5" />
                  </Button>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7 text-slate-300 hover:text-white hover:bg-slate-800"
                    onClick={() => setZoomLevel(1.0)}
                    title="Reset Zoom"
                  >
                    <RotateCcw className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </div>
            </div>
          </CardHeader>

          <CardContent className="p-0 relative min-h-[500px]">
            {/* REQUIREMENT 1 & 5: Empty / No-Connection State when disconnected in Live Mode */}
            {mode === "live" && !hasLiveDevices ? (
              <div className="flex flex-col items-center justify-center p-14 text-center">
                <div className="relative mb-5 flex h-20 w-20 items-center justify-center rounded-3xl bg-slate-800/80 border border-slate-700/60 shadow-inner">
                  <Radar className="h-10 w-10 text-emerald-400 animate-pulse" />
                  <span className="absolute -top-1 -right-1 flex h-4 w-4">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-4 w-4 bg-emerald-500"></span>
                  </span>
                </div>

                <h3 className="text-xl font-bold text-slate-100 tracking-tight">
                  No Connected Devices Detected
                </h3>
                <p className="mt-2 text-sm text-slate-400 max-w-md leading-relaxed">
                  Start network capture or connect a device to view the live network map.
                </p>

                <div className="mt-6 flex flex-col sm:flex-row items-center gap-3">
                  <Button
                    size="lg"
                    onClick={handleToggleCapture}
                    disabled={togglingCapture}
                    className="bg-emerald-600 hover:bg-emerald-700 text-white font-semibold px-6 shadow-lg shadow-emerald-950/40 gap-2"
                  >
                    {togglingCapture ? (
                      <RefreshCw className="h-4 w-4 animate-spin" />
                    ) : (
                      <Play className="h-4 w-4 fill-current" />
                    )}
                    Enable Device Capture
                  </Button>

                  <Button
                    variant="outline"
                    size="lg"
                    onClick={() => {
                      setMode("demo")
                      localStorage.setItem("netguard_app_mode", "demo")
                      window.dispatchEvent(new CustomEvent("netguard:mode-change", { detail: { mode: "demo" } }))
                    }}
                    className="border-slate-700 bg-slate-800/50 text-slate-300 hover:bg-slate-800 hover:text-white gap-2"
                  >
                    <Sparkles className="h-4 w-4 text-indigo-400" />
                    View Demo Topology
                  </Button>
                </div>

                {/* Real-time Environment Telemetry Footer */}
                <div className="mt-8 grid grid-cols-1 sm:grid-cols-3 gap-3 w-full max-w-xl text-left">
                  <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                    <div className="text-[10px] uppercase font-semibold text-slate-500">Npcap Driver</div>
                    <div className="text-xs font-semibold text-emerald-400 flex items-center gap-1.5 mt-0.5">
                      <CheckCircle2 className="h-3.5 w-3.5" />
                      {captureStatus?.npcap_installed ? "Installed & Active" : "Detecting driver..."}
                    </div>
                  </div>

                  <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                    <div className="text-[10px] uppercase font-semibold text-slate-500">Active Adapter</div>
                    <div className="text-xs font-semibold text-slate-200 truncate mt-0.5">
                      {captureStatus?.active_interface?.name || "Local Network Adapter"}
                    </div>
                  </div>

                  <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                    <div className="text-[10px] uppercase font-semibold text-slate-500">Capture Architecture</div>
                    <div className="text-xs font-semibold text-slate-200 mt-0.5">
                      Zero-Trust Flow Sniffer
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              /* Stable Rendered SVG Canvas with Arrowheads and Flow Particles */
              <div className="relative w-full overflow-hidden">
                <svg
                  viewBox="0 0 960 520"
                  className="w-full h-auto min-h-[480px] select-none transition-transform duration-200"
                  style={{
                    background: "radial-gradient(circle at center, #0f172a 0%, #020617 100%)",
                    transform: `scale(${zoomLevel})`,
                    transformOrigin: "center center",
                  }}
                >
                  <defs>
                    {/* Directional Arrowheads */}
                    <marker
                      id="arrow-normal"
                      viewBox="0 0 10 10"
                      refX="26"
                      refY="5"
                      markerWidth="6"
                      markerHeight="6"
                      orient="auto-start-reverse"
                    >
                      <path d="M 0 1.5 L 10 5 L 0 8.5 z" fill="#6366f1" />
                    </marker>

                    <marker
                      id="arrow-threat"
                      viewBox="0 0 10 10"
                      refX="26"
                      refY="5"
                      markerWidth="6"
                      markerHeight="6"
                      orient="auto-start-reverse"
                    >
                      <path d="M 0 1.5 L 10 5 L 0 8.5 z" fill="#f43f5e" />
                    </marker>

                    <marker
                      id="arrow-dns"
                      viewBox="0 0 10 10"
                      refX="26"
                      refY="5"
                      markerWidth="6"
                      markerHeight="6"
                      orient="auto-start-reverse"
                    >
                      <path d="M 0 1.5 L 10 5 L 0 8.5 z" fill="#38bdf8" />
                    </marker>

                    {/* Glow filter for highlighted nodes */}
                    <filter id="glow-filter" x="-20%" y="-20%" width="140%" height="140%">
                      <feGaussianBlur stdDeviation="3.5" result="blur" />
                      <feComposite in="SourceGraphic" in2="blur" operator="over" />
                    </filter>
                  </defs>

                  {/* Flow Links */}
                  {topologyData?.links.map((link, idx) => {
                    const src = nodePositions.get(link.source)
                    const tgt = nodePositions.get(link.target)
                    if (!src || !tgt) return null

                    const isThreat = link.is_threat || link.is_attack_path || link.status === "alert"
                    const isDNS = link.protocol === "DNS" || link.ports?.includes(53)
                    const isSelected = selectedLink === link

                    const strokeColor = isThreat ? "#f43f5e" : isDNS ? "#38bdf8" : "#6366f1"
                    const arrowMarker = isThreat ? "url(#arrow-threat)" : isDNS ? "url(#arrow-dns)" : "url(#arrow-normal)"

                    // Curved quadratic bezier path if reverse flow exists, avoiding line collision
                    const dx = tgt.x - src.x
                    const dy = tgt.y - src.y
                    const len = Math.sqrt(dx * dx + dy * dy) || 1
                    const nx = -dy / len
                    const ny = dx / len
                    const curveOffset = link.has_reverse_flow ? (src.x <= tgt.x ? 28 : -28) : 0

                    const midX = (src.x + tgt.x) / 2 + nx * curveOffset
                    const midY = (src.y + tgt.y) / 2 + ny * curveOffset

                    const pathD =
                      curveOffset !== 0
                        ? `M ${src.x} ${src.y} Q ${midX} ${midY} ${tgt.x} ${tgt.y}`
                        : `M ${src.x} ${src.y} L ${tgt.x} ${tgt.y}`

                    const linkKey = `link-${link.source}-${link.target}-${idx}`

                    return (
                      <g
                        key={linkKey}
                        className="cursor-pointer transition-opacity hover:opacity-100"
                        onClick={() => setSelectedLink(link)}
                      >
                        {/* Background Base Track */}
                        <path
                          d={pathD}
                          fill="none"
                          stroke={strokeColor}
                          strokeWidth={isSelected ? 3.5 : isThreat ? 2.5 : 1.6}
                          strokeOpacity={isSelected ? 0.9 : isThreat ? 0.75 : 0.4}
                          markerEnd={arrowMarker}
                        />

                        {/* Animated Flowing Packet Pulse (Moving Particle) */}
                        <circle r={isThreat ? 3.5 : 2.8} fill={isThreat ? "#fb7185" : isDNS ? "#7dd3fc" : "#a5b4fc"}>
                          <animateMotion
                            path={pathD}
                            dur={isThreat ? "1.2s" : "2.2s"}
                            repeatCount="indefinite"
                          />
                        </circle>

                        {/* Midpoint Protocol Pill Badge */}
                        <g transform={`translate(${midX}, ${midY})`}>
                          <rect
                            x="-22"
                            y="-9"
                            width="44"
                            height="18"
                            rx="9"
                            fill={isThreat ? "#881337" : isDNS ? "#0c4a6e" : "#1e1b4b"}
                            stroke={strokeColor}
                            strokeWidth="1"
                          />
                          <text
                            x="0"
                            y="3.5"
                            textAnchor="middle"
                            fill={isThreat ? "#fecdd3" : isDNS ? "#bae6fd" : "#c7d2fe"}
                            fontSize="9"
                            fontFamily="monospace"
                            fontWeight="bold"
                          >
                            {link.protocol}
                          </text>
                        </g>
                      </g>
                    )
                  })}

                  {/* Device Nodes */}
                  {topologyData?.nodes.map((node) => {
                    const pos = nodePositions.get(node.id)
                    if (!pos) return null

                    const isSelected = selectedNode?.id === node.id
                    const isAttacker = node.status === "attacker" || node.role === "c2_server" || node.status === "hostile"
                    const isCompromised = node.status === "compromised" || node.status === "threat_detected" || node.threat_level === "CRITICAL"
                    const isGateway = node.role === "gateway" || node.role === "router"
                    const isDNS = node.role === "dns"

                    let ringColor = "#10b981" // emerald
                    let fillColor = "#064e3b"

                    if (isAttacker) {
                      ringColor = "#f43f5e"
                      fillColor = "#881337"
                    } else if (isCompromised) {
                      ringColor = "#f59e0b"
                      fillColor = "#78350f"
                    } else if (isGateway) {
                      ringColor = "#818cf8"
                      fillColor = "#312e81"
                    } else if (isDNS) {
                      ringColor = "#38bdf8"
                      fillColor = "#0c4a6e"
                    }

                    return (
                      <g
                        key={`node-${node.id}`}
                        transform={`translate(${pos.x}, ${pos.y})`}
                        className="cursor-pointer transition-transform hover:scale-105"
                        onClick={() => setSelectedNode(node)}
                      >
                        {/* Outer Glow Halo */}
                        {(isSelected || isAttacker || isCompromised) && (
                          <circle
                            r="28"
                            fill="none"
                            stroke={ringColor}
                            strokeWidth="2"
                            strokeOpacity="0.4"
                            className="animate-ping"
                          />
                        )}

                        {/* Node circle */}
                        <circle
                          r={isSelected ? "22" : "19"}
                          fill={fillColor}
                          stroke={ringColor}
                          strokeWidth={isSelected ? "3" : "2"}
                          filter={isSelected || isAttacker ? "url(#glow-filter)" : undefined}
                        />

                        {/* Node icon */}
                        <g transform="translate(-8, -8)" className="pointer-events-none text-white">
                          {getNodeIcon(node)}
                        </g>

                        {/* Primary Label beneath node */}
                        <text
                          y="32"
                          textAnchor="middle"
                          fill="#f8fafc"
                          fontSize="11"
                          fontWeight="600"
                        >
                          {node.label.length > 24 ? node.label.substring(0, 22) + "…" : node.label}
                        </text>

                        {/* IP Address sub-label */}
                        <text
                          y="45"
                          textAnchor="middle"
                          fill="#94a3b8"
                          fontSize="9.5"
                          fontFamily="monospace"
                        >
                          {node.ip}
                        </text>
                      </g>
                    )
                  })}
                </svg>
              </div>
            )}
          </CardContent>
        </Card>
      ) : (
        /* Structured Table View */
        <div className="grid gap-6 lg:grid-cols-2">
          <Card className="border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900">
            <CardHeader className="p-4 border-b border-slate-200 dark:border-slate-800">
              <CardTitle className="text-sm font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <Laptop className="h-4 w-4 text-indigo-600 dark:text-indigo-400" />
                Connected Network Devices ({filteredNodes.length})
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="divide-y divide-slate-100 dark:divide-slate-800/80 max-h-[420px] overflow-y-auto">
                {filteredNodes.length === 0 ? (
                  <div className="p-6 text-center text-xs text-slate-500">
                    No devices match the selected filters.
                  </div>
                ) : (
                  filteredNodes.map((node) => (
                    <div
                      key={`table-node-${node.id}`}
                      onClick={() => setSelectedNode(node)}
                      className="flex items-center justify-between p-3.5 hover:bg-slate-50 dark:hover:bg-slate-800/50 cursor-pointer transition-colors"
                    >
                      <div className="flex items-center gap-3">
                        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-slate-100 dark:bg-slate-800">
                          {getNodeIcon(node)}
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                              {node.label}
                            </span>
                            <span className={`text-[10px] px-1.5 py-0.5 rounded-full border ${getNodeBadgeColor(node.status)}`}>
                              {(node.threat_level || node.status).toUpperCase()}
                            </span>
                          </div>
                          <div className="text-xs text-slate-500 font-mono mt-0.5">
                            {node.ip} • {node.device_type || node.role}
                          </div>
                        </div>
                      </div>

                      <div className="text-right text-xs">
                        <div className="font-semibold text-slate-800 dark:text-slate-200">
                          {(node.packets_in || 0) + (node.packets_out || 0) || node.packet_count || 0} pkts
                        </div>
                        <div className="text-slate-500 text-[11px]">
                          {((node.total_bytes || 0) / 1024).toFixed(1)} KB
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>

          <Card className="border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900">
            <CardHeader className="p-4 border-b border-slate-200 dark:border-slate-800">
              <CardTitle className="text-sm font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <Activity className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
                Observed Packet Flow Links ({topologyData?.links.length ?? 0})
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="divide-y divide-slate-100 dark:divide-slate-800/80 max-h-[420px] overflow-y-auto">
                {topologyData?.links.length === 0 ? (
                  <div className="p-6 text-center text-xs text-slate-500">
                    No active flow links recorded yet.
                  </div>
                ) : (
                  topologyData?.links.map((link, idx) => {
                    const srcNode = nodesMap.get(link.source)
                    const tgtNode = nodesMap.get(link.target)
                    return (
                      <div
                        key={`table-link-${link.source}-${link.target}-${idx}`}
                        onClick={() => setSelectedLink(link)}
                        className="flex items-center justify-between p-3.5 hover:bg-slate-50 dark:hover:bg-slate-800/50 cursor-pointer transition-colors"
                      >
                        <div>
                          <div className="flex items-center gap-2 text-xs font-semibold text-slate-900 dark:text-slate-100">
                            <span>{srcNode?.label || link.source}</span>
                            <ArrowRight className="h-3.5 w-3.5 text-slate-400" />
                            <span>{tgtNode?.label || link.target}</span>
                          </div>
                          <div className="text-[11px] text-slate-500 font-mono mt-0.5">
                            {link.protocol} {link.ports?.length ? `• Ports: ${link.ports.join(", ")}` : ""} {link.direction ? `• ${link.direction}` : ""}
                          </div>
                        </div>

                        <div className="text-right text-xs">
                          <Badge
                            variant="outline"
                            className={
                              link.is_threat
                                ? "border-rose-300 text-rose-600 dark:border-rose-800 dark:text-rose-400"
                                : "border-slate-200 text-slate-600 dark:border-slate-700"
                            }
                          >
                            {link.packet_count} pkts ({((link.byte_count || 0) / 1024).toFixed(1)} KB)
                          </Badge>
                        </div>
                      </div>
                    )
                  })
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Node Details Dialog */}
      <Dialog open={!!selectedNode} onOpenChange={(open) => !open && setSelectedNode(null)}>
        <DialogContent className="max-w-md border-slate-200 bg-white text-slate-900 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-100">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-base font-bold">
              {selectedNode && getNodeIcon(selectedNode)}
              <span>{selectedNode?.label}</span>
              {selectedNode && (
                <span className={`text-[10px] px-2 py-0.5 rounded-full border ${getNodeBadgeColor(selectedNode.status)}`}>
                  {(selectedNode.threat_level || selectedNode.status).toUpperCase()}
                </span>
              )}
            </DialogTitle>
            <DialogDescription className="text-xs text-slate-500 dark:text-slate-400 font-mono">
              IP: {selectedNode?.ip} • {selectedNode?.is_local ? "Internal Network Host" : "External Host"}
            </DialogDescription>
          </DialogHeader>

          {selectedNode && (
            <div className="space-y-4 pt-2 text-xs">
              <div className="grid grid-cols-2 gap-3 rounded-lg border border-slate-200 bg-slate-50 p-3 dark:border-slate-800 dark:bg-slate-800/40">
                <div>
                  <span className="text-slate-500">Device Type</span>
                  <div className="font-semibold text-slate-800 dark:text-slate-200">
                    {selectedNode.device_type || selectedNode.role}
                  </div>
                </div>
                <div>
                  <span className="text-slate-500">Total Packets</span>
                  <div className="font-semibold text-slate-800 dark:text-slate-200">
                    {(selectedNode.packets_in || 0) + (selectedNode.packets_out || 0) || selectedNode.packet_count || 0} pkts
                  </div>
                </div>
                <div>
                  <span className="text-slate-500">Data Volume</span>
                  <div className="font-semibold text-slate-800 dark:text-slate-200">
                    {((selectedNode.total_bytes || 0) / 1024).toFixed(2)} KB
                  </div>
                </div>
                <div>
                  <span className="text-slate-500">Active Protocols</span>
                  <div className="font-semibold text-slate-800 dark:text-slate-200">
                    {selectedNode.protocols?.join(", ") || "TCP"}
                  </div>
                </div>
              </div>

              {/* Connections for this node */}
              <div>
                <h4 className="font-semibold text-slate-900 dark:text-slate-100 mb-2">
                  Observed Traffic Relationships:
                </h4>
                <div className="space-y-1.5 max-h-36 overflow-y-auto">
                  {topologyData?.links
                    .filter((l) => l.source === selectedNode.id || l.target === selectedNode.id)
                    .map((l, i) => {
                      const peerId = l.source === selectedNode.id ? l.target : l.source
                      const peerNode = nodesMap.get(peerId)
                      const isOutgoing = l.source === selectedNode.id
                      return (
                        <div
                          key={`dialog-peer-${i}`}
                          className="flex items-center justify-between rounded-md border border-slate-200 bg-slate-50 p-2 dark:border-slate-800 dark:bg-slate-800/30"
                        >
                          <div className="flex items-center gap-1.5">
                            <span className="text-slate-500">{isOutgoing ? "➔ To:" : "⬅ From:"}</span>
                            <span className="font-medium text-slate-800 dark:text-slate-200">
                              {peerNode?.label || peerId}
                            </span>
                            <Badge variant="outline" className="text-[10px] py-0">
                              {l.protocol}
                            </Badge>
                          </div>
                          <span className="font-mono text-slate-500 text-[11px]">
                            {l.packet_count} pkts
                          </span>
                        </div>
                      )
                    })}
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-slate-200 dark:border-slate-800">
                <Button variant="outline" size="sm" onClick={() => setSelectedNode(null)}>
                  Close
                </Button>
                {onNavigateToTraffic && (
                  <Button
                    size="sm"
                    className="bg-indigo-600 hover:bg-indigo-700 text-white"
                    onClick={() => {
                      setSelectedNode(null)
                      onNavigateToTraffic()
                    }}
                  >
                    Inspect Packets
                    <ChevronRight className="ml-1 h-3.5 w-3.5" />
                  </Button>
                )}
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
