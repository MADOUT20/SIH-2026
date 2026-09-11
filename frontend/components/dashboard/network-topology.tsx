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
  Plus,
  Trash2,
  HelpCircle,
  Check,
  Search,
  HardDrive,
  Crosshair,
} from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
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
  DialogFooter,
} from "@/components/ui/dialog"
import {
  getNetworkTopology,
  getLiveCaptureStatus,
  startLivePacketCapture,
  stopLivePacketCapture,
  getDevices,
  deleteDevice,
  getDeviceTraffic,
  getDeviceThreatAssessment,
  type TopologyNode,
  type TopologyLink,
  type NetworkTopologyResponse,
  type CaptureStatusResponse,
  normalizeDevice,
  type NetworkDevice,
  type DeviceItem,
  type DeviceTrafficDetails,
  type DeviceThreatAssessment,
} from "@/lib/api"
import { useDevice } from "@/context/device-context"
import { deduplicateBy, createEntityKey } from "@/lib/dedup"

interface NetworkTopologyProps {
  onNavigateToTraffic?: () => void
}

export function NetworkTopologyPanel({ onNavigateToTraffic }: NetworkTopologyProps) {
  const { connectedDevice, openConnectModal, connectDevice: contextConnectDevice, disconnectDevice } = useDevice()
  const [mode, setMode] = useState<"live" | "demo">("live")
  const [topologyData, setTopologyData] = useState<NetworkTopologyResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null)
  const [selectedLink, setSelectedLink] = useState<TopologyLink | null>(null)
  const [roleFilter, setRoleFilter] = useState<string>("all")
  const [protocolFilter, setProtocolFilter] = useState<string>("all")
  const [viewMode, setViewMode] = useState<"visual" | "table">("visual")

  // Node Inspection Details State
  const [nodeTraffic, setNodeTraffic] = useState<DeviceTrafficDetails | null>(null)
  const [nodeAssessment, setNodeAssessment] = useState<DeviceThreatAssessment | null>(null)
  const [loadingNodeAssessment, setLoadingNodeAssessment] = useState(false)
  const [deletingDeviceId, setDeletingDeviceId] = useState<string | null>(null)
  const [connectingNodeId, setConnectingNodeId] = useState<string | null>(null)

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

  // Load deep device details when a node is selected
  const handleSelectNode = useCallback(
    async (node: TopologyNode) => {
      setSelectedNode(node)
      setNodeTraffic(null)
      setNodeAssessment(null)
      setLoadingNodeAssessment(true)

      const targetId = node.ip || node.id
      try {
        const [trafficRes, assessmentRes] = await Promise.all([
          getDeviceTraffic(targetId, mode).catch(() => null),
          getDeviceThreatAssessment(targetId, mode).catch(() => null),
        ])
        if (trafficRes) setNodeTraffic(trafficRes)
        if (assessmentRes) setNodeAssessment(assessmentRes)
      } catch (e) {
        console.error("Error fetching device details:", e)
      } finally {
        setLoadingNodeAssessment(false)
      }
    },
    [mode]
  )

  // Re-run threat assessment for the active node
  const handleRunThreatAssessment = async () => {
    if (!selectedNode) return
    setLoadingNodeAssessment(true)
    const targetId = selectedNode.ip || selectedNode.id
    try {
      const assessmentRes = await getDeviceThreatAssessment(targetId, mode)
      setNodeAssessment(assessmentRes)
      const trafficRes = await getDeviceTraffic(targetId, mode)
      setNodeTraffic(trafficRes)
    } catch (e: any) {
      console.error("Error evaluating threat assessment:", e)
    } finally {
      setLoadingNodeAssessment(false)
    }
  }

  // Handle quick connect of a node as active monitoring device
  const handleConnectNodeAsActive = async (node: TopologyNode) => {
    setConnectingNodeId(node.id)
    try {
      const devToConnect = normalizeDevice({
        id: node.id,
        name: node.label,
        ip: node.ip,
        mac: (node as any).mac || undefined,
        device_type: node.device_type || "Endpoint",
        description: `Connected via Network Topology map`,
      })
      if (devToConnect) {
        await contextConnectDevice(devToConnect, true)
        await fetchTopology()
      }
    } catch (err: any) {
      alert(err.message || "Failed to connect to device.")
    } finally {
      setConnectingNodeId(null)
    }
  }

  // Handle Delete Device
  const handleDeleteDevice = async (deviceId: string) => {
    setDeletingDeviceId(deviceId)
    try {
      await deleteDevice(deviceId)
      setSelectedNode(null)
      await fetchTopology()
    } catch (err: any) {
      alert(err.message || "Failed to remove device.")
    } finally {
      setDeletingDeviceId(null)
    }
  }

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

  // Unique deduplicated nodes list - Merges registered and observed devices with stable canonical identity
  const uniqueNodes = useMemo(() => {
    const rawNodes = topologyData?.nodes || []
    const deduped: TopologyNode[] = []
    const nodeIndexByIp = new Map<string, number>()
    const nodeIndexById = new Map<string, number>()

    for (const n of rawNodes) {
      if (!n) continue
      const rawIp = (n.ip || "").trim().toLowerCase()
      const rawId = (n.id || "").trim().toLowerCase()
      const canonicalIp = rawIp || (rawId.startsWith("dev_") ? rawId.replace("dev_", "").replace(/_/g, ".") : rawId)
      const canonicalId = rawId || (rawIp ? `dev_${rawIp.replace(/[.:]/g, "_")}` : "")

      let existingIndex = -1
      if (canonicalIp && nodeIndexByIp.has(canonicalIp)) {
        existingIndex = nodeIndexByIp.get(canonicalIp)!
      } else if (canonicalId && nodeIndexById.has(canonicalId)) {
        existingIndex = nodeIndexById.get(canonicalId)!
      } else if (rawIp && nodeIndexByIp.has(rawIp)) {
        existingIndex = nodeIndexByIp.get(rawIp)!
      } else if (rawId && nodeIndexById.has(rawId)) {
        existingIndex = nodeIndexById.get(rawId)!
      }

      if (existingIndex >= 0) {
        // Merge node properties instead of duplicating
        const existing = deduped[existingIndex]
        const merged: TopologyNode = {
          ...existing,
          ...n,
          id: existing.id || canonicalId || n.id,
          ip: existing.ip || canonicalIp || n.ip,
          label: (existing.is_registered && existing.label) ? existing.label : (n.label || existing.label),
          is_registered: Boolean(existing.is_registered || n.is_registered),
          status: (existing.status === "compromised" || existing.status === "attacker" || n.status === "compromised" || n.status === "attacker")
            ? (existing.status === "compromised" || existing.status === "attacker" ? existing.status : n.status)
            : (n.status || existing.status),
          threat_level: (existing.threat_level === "CRITICAL" || existing.threat_level === "HIGH" || n.threat_level === "CRITICAL" || n.threat_level === "HIGH")
            ? (existing.threat_level === "CRITICAL" || existing.threat_level === "HIGH" ? existing.threat_level : n.threat_level)
            : (n.threat_level || existing.threat_level),
          packets_in: Math.max(existing.packets_in || 0, n.packets_in || 0),
          packets_out: Math.max(existing.packets_out || 0, n.packets_out || 0),
          packet_count: Math.max(existing.packet_count || 0, n.packet_count || 0),
          total_bytes: Math.max(existing.total_bytes || 0, n.total_bytes || 0),
          protocols: Array.from(new Set([...(existing.protocols || []), ...(n.protocols || [])])),
          ports: Array.from(new Set([...(existing.ports || []), ...(n.ports || [])])),
          is_local: existing.is_local || n.is_local,
        }
        deduped[existingIndex] = merged
      } else {
        const newIndex = deduped.length
        deduped.push({
          ...n,
          id: canonicalId || n.id || `node_${newIndex}`,
          ip: canonicalIp || n.ip || "",
        })
        if (canonicalIp) nodeIndexByIp.set(canonicalIp, newIndex)
        if (canonicalId) nodeIndexById.set(canonicalId, newIndex)
        if (rawIp) nodeIndexByIp.set(rawIp, newIndex)
        if (rawId) nodeIndexById.set(rawId, newIndex)
      }
    }
    return deduped
  }, [topologyData?.nodes])

  // Filtered nodes
  const filteredNodes = useMemo(() => {
    return uniqueNodes.filter((node) => {
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
  }, [uniqueNodes, roleFilter, protocolFilter])

  // Nodes lookup map
  const nodesMap = useMemo(() => {
    const map = new Map<string, TopologyNode>()
    uniqueNodes.forEach((n) => {
      map.set(n.id, n)
      if (n.ip) map.set(n.ip, n)
      const cleanIp = (n.ip || "").trim().toLowerCase()
      const cleanId = (n.id || "").trim().toLowerCase()
      if (cleanIp) map.set(cleanIp, n)
      if (cleanId) map.set(cleanId, n)
    })
    return map
  }, [uniqueNodes])

  // Helper for clean, non-overlapping label formatting
  const formatNodeLabel = (label: string, maxLen = 18): string => {
    if (!label) return "Endpoint"
    const clean = label.trim()
    if (clean.length <= maxLen) return clean
    // Smart domain shortening: keep first segment and last two
    if (clean.includes(".")) {
      const parts = clean.split(".")
      if (parts.length > 2) {
        const short = `${parts[0]}…${parts.slice(-1).join(".")}`
        if (short.length <= maxLen) return short
      }
    }
    return clean.substring(0, maxLen - 1) + "…"
  }

  const formatNodeIp = (ip: string, maxLen = 16): string => {
    if (!ip) return ""
    const clean = ip.trim()
    if (clean.includes(":")) {
      // IPv6 — always abbreviate to first group::last group
      const parts = clean.split(":")
      if (parts.length >= 4) {
        return `${parts[0]}::${parts[parts.length - 1]}`
      }
      return clean.substring(0, 8) + "…"
    }
    // IPv4 — always fits within 16 chars
    return clean
  }

  // Reset layout positions when switching modes
  useEffect(() => {
    persistentPositionsRef.current.clear()
    tierSlotCountsRef.current = { 0: 0, 1: 0, 2: 0, 3: 0, 4: 0 }
  }, [mode])

  // Compute node coordinate positions with structured, multi-tier, collision-free deterministic layout
  const nodePositions = useMemo(() => {
    const positions = new Map<string, { x: number; y: number }>()
    const nodes = uniqueNodes
    if (nodes.length === 0) return positions

    const CANVAS_W = 920
    const CENTER_X = CANVAS_W / 2

    if (mode === "demo") {
      // Fixed deterministic layout for demonstration attack topology (920x480 viewport).
      // Row 1 (y=80):  C2 Server (210, 80) -> Edge Gateway (460, 80) -> Cloudflare DNS (710, 80)
      // Row 2 (y=220): Compromised Laptop (310, 220) [ACTIVE] -> Admin Workstation (610, 220)
      // Row 3 (y=360): Domain Controller (310, 360) -> Database Server (610, 360)
      const demoCoords: Record<string, { x: number; y: number }> = {
        "185.220.101.5": { x: 210, y: 80 },  // C2 External Threat / Attacker
        "192.168.1.1":   { x: 460, y: 80 },  // Edge Gateway / Router
        "1.1.1.1":        { x: 710, y: 80 },  // Cloudflare DNS resolver
        "192.168.1.105": { x: 310, y: 220 }, // Compromised Laptop (Active Monitor)
        "192.168.1.45":  { x: 610, y: 220 }, // Admin Workstation
        "192.168.1.10":  { x: 310, y: 360 }, // Domain Controller
        "192.168.1.200": { x: 610, y: 360 }, // Database Server
      }

      let overflowIdx = 0
      nodes.forEach((n) => {
        const key = (n.ip || n.id || "").trim()
        const canonicalIp = (n.ip || "").trim()
        const canonicalId = (n.id || "").trim()

        let coord = demoCoords[key] || demoCoords[canonicalIp] || demoCoords[canonicalId]
        if (!coord) {
          if (persistentPositionsRef.current.has(key)) {
            coord = persistentPositionsRef.current.get(key)!
          } else if (canonicalIp && persistentPositionsRef.current.has(canonicalIp)) {
            coord = persistentPositionsRef.current.get(canonicalIp)!
          } else {
            // Deterministic overflow placement for extra nodes
            const row = Math.floor(overflowIdx / 3)
            const col = overflowIdx % 3
            coord = { x: 210 + col * 250, y: 360 + (row + 1) * 110 }
            overflowIdx++
            persistentPositionsRef.current.set(key, coord)
            if (canonicalIp) persistentPositionsRef.current.set(canonicalIp, coord)
            if (canonicalId) persistentPositionsRef.current.set(canonicalId, coord)
          }
        }

        positions.set(n.id, coord)
        if (n.ip) positions.set(n.ip, coord)
        if (canonicalIp) positions.set(canonicalIp, coord)
        if (canonicalId) positions.set(canonicalId, coord)
      })
      return positions
    }

    // LIVE MODE: Deterministic 3-Tier Network Tree (bounded within 920x480 canvas)
    // Tier 0 (Y=80):  Gateways / Routers / DNS
    // Tier 1 (Y=220): Active Monitored Workstation / Local Host
    // Tier 2 (Y=360): Discovered Endpoints & Observed Peers

    const gateways: TopologyNode[] = []
    const localNodes: TopologyNode[] = []
    const peerNodes: TopologyNode[] = []

    nodes.forEach((node) => {
      const labelLower = (node.label || "").toLowerCase()
      const roleLower = (node.role || "").toLowerCase()
      const ip = (node.ip || "").trim()

      if (
        roleLower === "gateway" ||
        roleLower === "router" ||
        roleLower === "dns" ||
        ip.endsWith(".1") ||
        labelLower.includes("gateway") ||
        labelLower.includes("router")
      ) {
        gateways.push(node)
      } else if (
        node.is_local ||
        (connectedDevice && (connectedDevice.id === node.id || connectedDevice.ip === node.ip)) ||
        roleLower === "workstation" ||
        roleLower === "localhost" ||
        labelLower.includes("laptop") ||
        labelLower.includes("workstation")
      ) {
        localNodes.push(node)
      } else {
        peerNodes.push(node)
      }
    })

    // Helper to position a tier array horizontally centered
    const positionTier = (tierNodes: TopologyNode[], yPos: number) => {
      const count = tierNodes.length
      if (count === 0) return
      const SPACING = Math.min(240, Math.max(190, Math.floor(760 / count)))
      tierNodes.forEach((node, i) => {
        const key = (node.ip || node.id || "").trim()
        const canonicalIp = (node.ip || "").trim()

        if (persistentPositionsRef.current.has(key)) {
          const cached = persistentPositionsRef.current.get(key)!
          positions.set(node.id, cached)
          if (node.ip) positions.set(node.ip, cached)
          return
        }
        if (canonicalIp && persistentPositionsRef.current.has(canonicalIp)) {
          const cached = persistentPositionsRef.current.get(canonicalIp)!
          positions.set(node.id, cached)
          if (node.ip) positions.set(node.ip, cached)
          return
        }

        const x = CENTER_X + (i - (count - 1) / 2) * SPACING
        const coord = { x, y: yPos }
        persistentPositionsRef.current.set(key, coord)
        if (canonicalIp) persistentPositionsRef.current.set(canonicalIp, coord)
        positions.set(node.id, coord)
        if (node.ip) positions.set(node.ip, coord)
      })
    }

    positionTier(gateways, 80)
    positionTier(localNodes.length > 0 ? localNodes : (gateways.length === 0 && peerNodes.length > 0 ? [peerNodes[0]] : []), 220)
    const remainingPeers = localNodes.length === 0 && gateways.length === 0 ? peerNodes.slice(1) : peerNodes
    positionTier(remainingPeers, 360)

    return positions
  }, [uniqueNodes, mode, connectedDevice])

  const canvasWidth = 920
  const canvasHeight = 480

  const viewBoxString = useMemo(() => {
    const vbW = canvasWidth / zoomLevel
    const vbH = canvasHeight / zoomLevel
    const vbX = (canvasWidth - vbW) / 2
    const vbY = (canvasHeight - vbH) / 2
    return `${vbX} ${vbY} ${vbW} ${vbH}`
  }, [zoomLevel])

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

  const getNodeBadgeColor = (status: string, threatLevel?: string) => {
    const s = (status || "").toLowerCase()
    const t = (threatLevel || "").toUpperCase()
    if (s === "attacker" || s === "hostile" || t === "CRITICAL" || t === "MALICIOUS / THREAT DETECTED") {
      return "bg-rose-500/15 text-rose-600 border-rose-300 dark:bg-rose-950/40 dark:text-rose-300 dark:border-rose-800"
    }
    if (s === "compromised" || s === "threat_detected" || t === "HIGH" || t === "HIGH RISK") {
      return "bg-amber-500/15 text-amber-600 border-amber-300 dark:bg-amber-950/40 dark:text-amber-300 dark:border-amber-800"
    }
    if (s === "warning" || t === "SUSPICIOUS" || t === "MEDIUM") {
      return "bg-amber-500/15 text-amber-600 border-amber-300 dark:bg-amber-950/40 dark:text-amber-300 dark:border-amber-800"
    }
    if (s === "not_observed" || t === "NOT ASSESSED") {
      return "bg-slate-500/15 text-slate-600 border-slate-300 dark:bg-slate-950/40 dark:text-slate-400 dark:border-slate-800"
    }
    return "bg-emerald-500/15 text-emerald-600 border-emerald-300 dark:bg-emerald-950/40 dark:text-emerald-300 dark:border-emerald-800"
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
                Interactive topology of active endpoints, hardware gateways, connected targets, and observed packet flows
              </p>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {/* Connect Device Button */}
          <Button
            size="sm"
            onClick={openConnectModal}
            className="h-8 gap-1.5 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold shadow-sm"
          >
            <Wifi className="h-3.5 w-3.5" />
            Connect Device
          </Button>

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
            <span className="font-bold uppercase tracking-wider text-indigo-700 dark:text-indigo-300">DEMO NETWORK MAP ACTIVE:</span> Displaying deterministic enterprise attack scenario (External C2 ➔ Edge Firewall ➔ Compromised Internal Laptop ➔ Domain Controller & Core DB). These simulated endpoints allow testing forensic graph tracing without live traffic.
          </div>
        </div>
      ) : (
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 rounded-xl border border-emerald-200 bg-emerald-50/70 p-3.5 text-emerald-950 dark:border-emerald-900/50 dark:bg-emerald-950/20 dark:text-emerald-200">
          <div className="flex items-center gap-3">
            <CheckCircle2 className="h-5 w-5 shrink-0 text-emerald-600 dark:text-emerald-400" />
            <div className="text-xs leading-relaxed">
              <span className="font-bold uppercase tracking-wider text-emerald-700 dark:text-emerald-300">LIVE NETWORK MAP ACTIVE:</span> Inspecting real packets and discovered endpoints from this machine.
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
              <span className="text-xs font-medium text-slate-600 dark:text-slate-400">Observed & Connected Devices</span>
              <Laptop className="h-4 w-4 text-indigo-500" />
            </div>
            <div className="mt-2 text-2xl font-bold text-slate-900 dark:text-slate-100">
              {topologyData?.total_devices ?? 0}
            </div>
            <div className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
              {topologyData?.nodes.filter((n) => n.is_local).length ?? 0} Local / Connected Host(s)
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
              {topologyData?.nodes.filter((n) => n.status === "compromised" || n.status === "attacker" || n.threat_level === "CRITICAL" || n.threat_level === "HIGH" || n.threat_level === "MALICIOUS / THREAT DETECTED").length ?? 0}
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
              <SelectItem value="local">Local & Connected</SelectItem>
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
            <span>Clean / Active</span>
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
            <span>Threat / Malicious</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-slate-400"></span>
            <span>Not Observed</span>
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
                  Click any node to view device connectivity status, socket traffic, and ML malware threat assessment
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
                  Start network capture or click "Connect Device" to discover and monitor devices on the network.
                </p>

                <div className="mt-6 flex flex-col sm:flex-row items-center gap-3">
                  <Button
                    size="lg"
                    onClick={openConnectModal}
                    className="bg-indigo-600 hover:bg-indigo-700 text-white font-semibold px-6 shadow-lg shadow-indigo-950/40 gap-2"
                  >
                    <Wifi className="h-4 w-4" />
                    Connect Device
                  </Button>

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
                </div>
              </div>
            ) : (
              /* Stable Rendered SVG Canvas with Arrowheads and Multi-Column Layout */
              <div className="relative w-full h-[480px] overflow-hidden">
                <svg
                  viewBox={viewBoxString}
                  className="w-full h-[480px] select-none"
                  style={{
                    background: "radial-gradient(circle at center, #0f172a 0%, #020617 100%)",
                  }}
                >
                  <defs>
                    <marker
                      id="arrow-normal"
                      viewBox="0 0 10 10"
                      refX="25"
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
                      refX="25"
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
                      refX="25"
                      refY="5"
                      markerWidth="6"
                      markerHeight="6"
                      orient="auto-start-reverse"
                    >
                      <path d="M 0 1.5 L 10 5 L 0 8.5 z" fill="#38bdf8" />
                    </marker>

                    <filter id="glow-filter" x="-20%" y="-20%" width="140%" height="140%">
                      <feGaussianBlur stdDeviation="3.5" result="blur" />
                      <feComposite in="SourceGraphic" in2="blur" operator="over" />
                    </filter>
                  </defs>

                  {/* Flow Links — deduplicated and with deterministic per-pair badge offsets */}
                  {(() => {
                    // Deduplicate links: same source+target+protocol is rendered only once.
                    // Genuinely different protocol flows are kept distinct.
                    const seenLinkKeys = new Set<string>()
                    const deduped = (topologyData?.links || []).filter((link) => {
                      const fwd = `${link.source}||${link.target}||${link.protocol}`
                      if (seenLinkKeys.has(fwd)) return false
                      seenLinkKeys.add(fwd)
                      return true
                    })

                    // Build a map: pairKey -> [link, link, ...] to detect parallel links
                    // and assign deterministic curve offsets so badges don't stack.
                    const pairCount = new Map<string, number>()
                    const pairIndex = new Map<string, number>()
                    deduped.forEach((link) => {
                      // Canonical pair key: always sort source/target alphabetically
                      const pairKey = [link.source, link.target].sort().join("||")
                      pairCount.set(pairKey, (pairCount.get(pairKey) || 0) + 1)
                    })

                    return deduped.map((link, idx) => {
                      const src = nodePositions.get(link.source)
                      const tgt = nodePositions.get(link.target)
                      if (!src || !tgt) return null

                      const isThreat = link.is_threat || link.is_attack_path || link.status === "alert"
                      const isDNS = link.protocol === "DNS" || link.ports?.includes(53)
                      const isSelected = selectedLink === link

                      const strokeColor = isThreat ? "#f43f5e" : isDNS ? "#38bdf8" : "#6366f1"
                      const arrowMarker = isThreat ? "url(#arrow-threat)" : isDNS ? "url(#arrow-dns)" : "url(#arrow-normal)"

                      // Determine deterministic curve offset for this link among parallel links
                      const pairKey = [link.source, link.target].sort().join("||")
                      const nParallel = pairCount.get(pairKey) || 1
                      const myIdx = pairIndex.get(pairKey) || 0
                      pairIndex.set(pairKey, myIdx + 1)

                      const dx = tgt.x - src.x
                      const dy = tgt.y - src.y
                      const len = Math.sqrt(dx * dx + dy * dy) || 1
                      // Perpendicular unit vector
                      const nx = -dy / len
                      const ny = dx / len

                      // Base curve offset: spread parallel links by 30px each
                      // Centre them symmetrically: offsets = -step*(n-1)/2, ..., step*(n-1)/2
                      const CURVE_STEP = 30
                      const baseOffset = nParallel > 1
                        ? -CURVE_STEP * (nParallel - 1) / 2 + myIdx * CURVE_STEP
                        : 0

                      // Extra override for the specific C2 cross-link in demo
                      const isC2Cross =
                        (link.source.includes("105") && link.target.includes("185.220")) ||
                        (link.source.includes("185.220") && link.target.includes("105"))

                      let pathD: string
                      let badgeX: number
                      let badgeY: number

                      if (isC2Cross) {
                        // Arc above the gateway, clearly avoiding node labels
                        const arcY = Math.min(src.y, tgt.y) - 80
                        const midX = (src.x + tgt.x) / 2
                        pathD = `M ${src.x} ${src.y} Q ${midX} ${arcY} ${tgt.x} ${tgt.y}`
                        badgeX = midX
                        badgeY = arcY + 12
                      } else if (nParallel > 1 || link.has_reverse_flow) {
                        // Curved path to separate parallel / bidirectional links
                        const curveOffset = baseOffset + (link.has_reverse_flow ? (src.x <= tgt.x ? 22 : -22) : 0)
                        const midX = (src.x + tgt.x) / 2 + nx * curveOffset
                        const midY = (src.y + tgt.y) / 2 + ny * curveOffset
                        pathD = `M ${src.x} ${src.y} Q ${midX} ${midY} ${tgt.x} ${tgt.y}`
                        // Place badge at t=0.45 on the bezier, offset perpendicular by 12px to avoid the path
                        const t = 0.45
                        const bx = (1-t)*(1-t)*src.x + 2*(1-t)*t*midX + t*t*tgt.x
                        const by = (1-t)*(1-t)*src.y + 2*(1-t)*t*midY + t*t*tgt.y
                        // Offset badge perpendicular to path to avoid line overlap
                        const badgeOffset = curveOffset >= 0 ? 14 : -14
                        badgeX = bx + nx * badgeOffset
                        badgeY = by + ny * badgeOffset
                      } else {
                        pathD = `M ${src.x} ${src.y} L ${tgt.x} ${tgt.y}`
                        // Place badge at 40% along the link, offset 12px perpendicular to avoid line
                        const t = 0.40
                        badgeX = (1 - t) * src.x + t * tgt.x + nx * 12
                        badgeY = (1 - t) * src.y + t * tgt.y + ny * 12
                      }

                      const linkKey = createEntityKey("topo-link", `${link.source}-${link.target}`, [link.protocol, String(idx)])

                      return (
                        <g
                          key={linkKey}
                          className="cursor-pointer"
                          onClick={() => setSelectedLink(link)}
                        >
                          <path
                            d={pathD}
                            fill="none"
                            stroke={strokeColor}
                            strokeWidth={isSelected ? 3.5 : isThreat ? 2.5 : 1.6}
                            strokeOpacity={isSelected ? 0.9 : isThreat ? 0.75 : 0.4}
                            markerEnd={arrowMarker}
                          />

                          <circle r={isThreat ? 3.5 : 2.8} fill={isThreat ? "#fb7185" : isDNS ? "#7dd3fc" : "#a5b4fc"}>
                            <animateMotion
                              path={pathD}
                              dur={isThreat ? "1.2s" : "2.2s"}
                              repeatCount="indefinite"
                            />
                          </circle>

                          <g transform={`translate(${badgeX}, ${badgeY})`}>
                            <rect
                              x="-20"
                              y="-8.5"
                              width="40"
                              height="17"
                              rx="8.5"
                              fill={isThreat ? "#881337" : isDNS ? "#0c4a6e" : "#1e1b4b"}
                              stroke={strokeColor}
                              strokeWidth="1"
                            />
                            <text
                              x="0"
                              y="3"
                              textAnchor="middle"
                              fill={isThreat ? "#fecdd3" : isDNS ? "#bae6fd" : "#c7d2fe"}
                              fontSize="8.5"
                              fontFamily="monospace"
                              fontWeight="bold"
                            >
                              {link.protocol}
                            </text>
                          </g>
                        </g>
                      )
                    })
                  })()}

                  {/* Compact Professional Device Card Nodes */}
                  {uniqueNodes.map((node, nodeIdx) => {
                    const pos = nodePositions.get(node.id)
                    if (!pos) return null

                    const isSelected = selectedNode?.id === node.id
                    const isAttacker = node.status === "attacker" || node.role === "c2_server" || node.status === "hostile"
                    const isCompromised = node.status === "compromised" || node.status === "threat_detected" || node.threat_level === "CRITICAL" || node.threat_level === "MALICIOUS / THREAT DETECTED"
                    const isGateway = node.role === "gateway" || node.role === "router"
                    const isDNS = node.role === "dns"

                    const isCurrentActiveTarget = Boolean(
                      connectedDevice && (connectedDevice.id === node.id || connectedDevice.ip === node.ip)
                    )

                    const nodeKey = createEntityKey("topo-node", node.id, [node.ip, String(nodeIdx)])

                    const strokeColor = isCurrentActiveTarget
                      ? "#10b981"
                      : isAttacker
                      ? "#f43f5e"
                      : isCompromised
                      ? "#f59e0b"
                      : isGateway
                      ? "#6366f1"
                      : isDNS
                      ? "#38bdf8"
                      : "#334155"

                    const bgFill = isCurrentActiveTarget
                      ? "#06271c"
                      : isAttacker
                      ? "#2a0d18"
                      : isCompromised
                      ? "#281a04"
                      : isGateway
                      ? "#1e1b4b"
                      : isDNS
                      ? "#0c4a6e"
                      : "#0f172a"

                    return (
                      <g
                        key={nodeKey}
                        transform={`translate(${pos.x}, ${pos.y})`}
                        className="cursor-pointer group"
                        onClick={() => handleSelectNode(node)}
                      >
                        <title>{`${node.label}\nIP: ${node.ip}\nRole: ${node.role || node.device_type || "Endpoint"}\nPackets: ${(node.packets_in || 0) + (node.packets_out || 0) || node.packet_count || 0}\nStatus: ${node.threat_level || node.status}`}</title>

                        {/* Outer Glowing / Pulsing Orbit Ring */}
                        {(isCurrentActiveTarget || isAttacker || isCompromised) && (
                          <circle
                            r="33"
                            fill="none"
                            stroke={strokeColor}
                            strokeWidth="1.2"
                            strokeDasharray="4 3"
                            opacity="0.8"
                          />
                        )}

                        {/* Primary Circular Device Node Circle */}
                        <circle
                          r="25"
                          fill={bgFill}
                          stroke={strokeColor}
                          strokeWidth={isCurrentActiveTarget || isSelected ? "3" : "2"}
                          className="transition-transform group-hover:scale-110 duration-200"
                          filter={isSelected || isCurrentActiveTarget || isAttacker ? "url(#glow-filter)" : undefined}
                        />

                        {/* Inner Centered Device Icon */}
                        <g transform="translate(-10, -10)" className="text-white pointer-events-none">
                          {getNodeIcon(node)}
                        </g>

                        {/* Label Centered Below Circle */}
                        <text
                          x="0"
                          y="41"
                          textAnchor="middle"
                          fill="#f8fafc"
                          fontSize="10"
                          fontWeight="700"
                          className="pointer-events-none select-none tracking-tight"
                        >
                          {formatNodeLabel(node.label, 18)}
                        </text>

                        {/* IP Address Centered Below Label */}
                        <text
                          x="0"
                          y="53"
                          textAnchor="middle"
                          fill="#94a3b8"
                          fontSize="8.5"
                          fontFamily="monospace"
                          className="pointer-events-none select-none"
                        >
                          {node.ip || "0.0.0.0"}
                        </text>

                        {/* Compact Status Pill Badge Line */}
                        <g transform="translate(-50, 59)">
                          {isCurrentActiveTarget ? (
                            <>
                              <rect width="100" height="15" rx="7.5" fill="#064e3b" stroke="#10b981" strokeWidth="0.8" />
                              <text x="50" y="10.5" textAnchor="middle" fill="#a7f3d0" fontSize="7.5" fontWeight="700" fontFamily="monospace" className="pointer-events-none select-none tracking-wider">
                                ● ACTIVE MONITOR
                              </text>
                            </>
                          ) : isAttacker || isCompromised ? (
                            <>
                              <rect width="100" height="15" rx="7.5" fill="#881337" stroke="#f43f5e" strokeWidth="0.8" />
                              <text x="50" y="10.5" textAnchor="middle" fill="#fecdd3" fontSize="7.5" fontWeight="700" fontFamily="monospace" className="pointer-events-none select-none tracking-wider">
                                ⚠ THREAT DETECTED
                              </text>
                            </>
                          ) : isGateway ? (
                            <>
                              <rect width="100" height="15" rx="7.5" fill="#1e1b4b" stroke="#6366f1" strokeWidth="0.8" />
                              <text x="50" y="10.5" textAnchor="middle" fill="#c7d2fe" fontSize="7.5" fontWeight="700" fontFamily="monospace" className="pointer-events-none select-none tracking-wider">
                                GATEWAY / ROUTER
                              </text>
                            </>
                          ) : (
                            <>
                              <rect width="100" height="15" rx="7.5" fill="#1e293b" stroke="#334155" strokeWidth="0.8" />
                              <text x="50" y="10.5" textAnchor="middle" fill="#94a3b8" fontSize="7.5" fontWeight="700" fontFamily="monospace" className="pointer-events-none select-none tracking-wider">
                                ● OBSERVED ENDPOINT
                              </text>
                            </>
                          )}
                        </g>
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
                    No devices match the selected filters. Click "Connect Device" to discover local devices.
                  </div>
                ) : (
                  filteredNodes.map((node) => (
                    <div
                      key={createEntityKey("table-node", node.id, [node.ip])}
                      onClick={() => handleSelectNode(node)}
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
                            <span className={`text-[10px] px-1.5 py-0.5 rounded-full border ${getNodeBadgeColor(node.status, node.threat_level)}`}>
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
                        key={createEntityKey("table-link", `${link.source}-${link.target}`, [link.protocol, String(idx)])}
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

      {/* Comprehensive Device Inspection & Threat Assessment Dialog */}
      <Dialog open={!!selectedNode} onOpenChange={(open) => !open && setSelectedNode(null)}>
        <DialogContent className="max-w-2xl border-slate-200 bg-white text-slate-900 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-100 p-0 overflow-hidden">
          <DialogHeader className="p-5 pb-3 border-b border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-950/40">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-slate-100 dark:bg-slate-800">
                  {selectedNode && getNodeIcon(selectedNode)}
                </div>
                <div>
                  <DialogTitle className="flex items-center gap-2 text-base font-bold text-slate-900 dark:text-slate-100">
                    <span>{selectedNode?.label}</span>
                    {nodeAssessment && (
                      <Badge
                        variant="outline"
                        className={getNodeBadgeColor(nodeAssessment.security_status, nodeAssessment.security_status)}
                      >
                        {nodeAssessment.security_status}
                      </Badge>
                    )}
                  </DialogTitle>
                  <DialogDescription className="text-xs text-slate-500 dark:text-slate-400 font-mono mt-0.5">
                    IP: {selectedNode?.ip} • {selectedNode?.device_type || selectedNode?.type || selectedNode?.role}
                  </DialogDescription>
                </div>
              </div>

              {selectedNode?.is_registered && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => selectedNode && handleDeleteDevice(selectedNode.ip || selectedNode.id)}
                  disabled={deletingDeviceId === (selectedNode?.ip || selectedNode?.id)}
                  className="h-7 text-xs text-rose-600 hover:text-rose-700 hover:bg-rose-50 border-rose-200 dark:border-rose-900/50"
                >
                  <Trash2 className="mr-1 h-3 w-3" />
                  Unregister
                </Button>
              )}
            </div>
          </DialogHeader>

          {selectedNode && (
            <div className="p-5 pt-3 space-y-4">
              <Tabs defaultValue="overview" className="w-full">
                <TabsList className="grid w-full grid-cols-3 h-8 text-xs bg-slate-100 dark:bg-slate-800">
                  <TabsTrigger value="overview">Device Telemetry</TabsTrigger>
                  <TabsTrigger value="traffic">Observed Sockets</TabsTrigger>
                  <TabsTrigger value="security">LSTM Threat Analysis</TabsTrigger>
                </TabsList>

                {/* Tab 1: Overview & Connectivity */}
                <TabsContent value="overview" className="space-y-3 pt-3 text-xs">
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    <div className="rounded-lg border border-slate-200 bg-slate-50/70 p-3 dark:border-slate-800 dark:bg-slate-800/40">
                      <span className="text-slate-500">Connectivity</span>
                      <div className="font-bold text-slate-800 dark:text-slate-200 mt-1 flex items-center gap-1.5">
                        <span className={`h-2 w-2 rounded-full ${nodeTraffic?.has_traffic ? "bg-emerald-500 animate-pulse" : "bg-slate-400"}`} />
                        {nodeTraffic?.connectivity_status || (selectedNode.status === "not_observed" ? "NOT OBSERVED" : "ACTIVE")}
                      </div>
                    </div>

                    <div className="rounded-lg border border-slate-200 bg-slate-50/70 p-3 dark:border-slate-800 dark:bg-slate-800/40">
                      <span className="text-slate-500">Packets Observed</span>
                      <div className="font-bold text-slate-800 dark:text-slate-200 mt-1">
                        {nodeTraffic ? nodeTraffic.packet_count : ((selectedNode.packets_in || 0) + (selectedNode.packets_out || 0) || selectedNode.packet_count || 0)} pkts
                      </div>
                    </div>

                    <div className="rounded-lg border border-slate-200 bg-slate-50/70 p-3 dark:border-slate-800 dark:bg-slate-800/40">
                      <span className="text-slate-500">Total Volume</span>
                      <div className="font-bold text-slate-800 dark:text-slate-200 mt-1">
                        {nodeTraffic ? ((nodeTraffic.byte_count || 0) / 1024).toFixed(1) : ((selectedNode.total_bytes || 0) / 1024).toFixed(1)} KB
                      </div>
                    </div>

                    <div className="rounded-lg border border-slate-200 bg-slate-50/70 p-3 dark:border-slate-800 dark:bg-slate-800/40">
                      <span className="text-slate-500">Device Location</span>
                      <div className="font-bold text-slate-800 dark:text-slate-200 mt-1">
                        {selectedNode.is_local ? "Local Network (LAN)" : "External / Remote"}
                      </div>
                    </div>
                  </div>

                  {/* Connected links for this node */}
                  <div>
                    <h4 className="font-semibold text-slate-900 dark:text-slate-100 mb-2">
                      Connected Network Flow Links:
                    </h4>
                    <div className="space-y-1.5 max-h-40 overflow-y-auto">
                      {topologyData?.links
                        .filter((l) => l.source === selectedNode.id || l.target === selectedNode.id)
                        .map((l, i) => {
                          const peerId = l.source === selectedNode.id ? l.target : l.source
                          const peerNode = nodesMap.get(peerId)
                          const isOutgoing = l.source === selectedNode.id
                          return (
                            <div
                              key={createEntityKey("dlg-peer", `${l.source}-${l.target}`, [l.protocol, String(i)])}
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
                                {l.packet_count} pkts ({((l.byte_count || 0) / 1024).toFixed(1)} KB)
                              </span>
                            </div>
                          )
                        })}
                      {(!topologyData?.links.some((l) => l.source === selectedNode.id || l.target === selectedNode.id)) && (
                        <div className="p-3 text-center text-slate-400 bg-slate-50 dark:bg-slate-800/20 rounded-md border border-dashed border-slate-200 dark:border-slate-800">
                          NO TRAFFIC OBSERVED for this device yet.
                        </div>
                      )}
                    </div>
                  </div>
                </TabsContent>

                {/* Tab 2: Observed Traffic & Sockets */}
                <TabsContent value="traffic" className="space-y-3 pt-3 text-xs">
                  {nodeTraffic && nodeTraffic.has_traffic ? (
                    <div className="space-y-3">
                      <div className="grid grid-cols-2 gap-3">
                        <div className="rounded-lg border border-slate-200 p-3 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/30">
                          <span className="text-slate-500 font-medium">Protocol Breakdown</span>
                          <div className="mt-1 flex flex-wrap gap-1.5">
                            {Object.entries(nodeTraffic.protocols || {}).map(([proto, cnt]) => (
                              <Badge key={proto} variant="secondary" className="text-[11px]">
                                {proto}: {cnt} pkts
                              </Badge>
                            ))}
                          </div>
                        </div>

                        <div className="rounded-lg border border-slate-200 p-3 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/30">
                          <span className="text-slate-500 font-medium">Observed Ports</span>
                          <div className="mt-1 flex flex-wrap gap-1.5">
                            {nodeTraffic.ports && nodeTraffic.ports.length > 0 ? (
                              nodeTraffic.ports.map((pt) => (
                                <Badge key={pt} variant="outline" className="text-[11px] font-mono">
                                  Port {pt}
                                </Badge>
                              ))
                            ) : (
                              <span className="text-slate-400">None</span>
                            )}
                          </div>
                        </div>
                      </div>

                      <div>
                        <span className="text-slate-500 font-medium block mb-1.5">Observed Socket Connections</span>
                        <div className="space-y-1.5 max-h-44 overflow-y-auto">
                          {(nodeTraffic.connections || []).map((conn, idx) => (
                            <div
                              key={createEntityKey("dlg-conn", `${conn.endpoint}-${conn.protocol}`, [String(idx)])}
                              className="flex items-center justify-between p-2 rounded-md border border-slate-200 bg-slate-50 dark:border-slate-800 dark:bg-slate-800/40 text-[11px]"
                            >
                              <div className="flex items-center gap-2">
                                <Badge variant="outline" className="text-[10px]">
                                  {conn.protocol || "TCP"}
                                </Badge>
                                <span className="font-mono font-semibold">{conn.endpoint}</span>
                                {conn.ports && conn.ports.length > 0 && (
                                  <span className="text-slate-400">({conn.ports.join(", ")})</span>
                                )}
                              </div>
                              <div className="text-right font-mono text-slate-500">
                                {conn.packet_count} pkts • {((conn.byte_count || 0) / 1024).toFixed(1)} KB
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="p-8 text-center bg-slate-50 dark:bg-slate-800/30 rounded-lg border border-dashed border-slate-200 dark:border-slate-800">
                      <Activity className="h-8 w-8 text-slate-400 mx-auto mb-2" />
                      <div className="font-bold text-slate-700 dark:text-slate-300">NO TRAFFIC OBSERVED</div>
                      <p className="text-slate-500 mt-1 max-w-sm mx-auto">
                        This device has not transmitted or received any network packets through the active capture adapter.
                      </p>
                    </div>
                  )}
                </TabsContent>

                {/* Tab 3: LSTM Malware & Threat Assessment */}
                <TabsContent value="security" className="space-y-3 pt-3 text-xs">
                  {loadingNodeAssessment ? (
                    <div className="p-8 text-center">
                      <RefreshCw className="h-6 w-6 animate-spin text-indigo-500 mx-auto mb-2" />
                      <span className="text-slate-500">Evaluating 27-feature PyTorch LSTM World Model...</span>
                    </div>
                  ) : nodeAssessment ? (
                    <div className="space-y-3">
                      <div className="flex items-center justify-between p-3 rounded-lg border border-slate-200 bg-slate-50/70 dark:border-slate-800 dark:bg-slate-800/40">
                        <div>
                          <div className="text-slate-500">Security Assessment State</div>
                          <div className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2 mt-0.5">
                            <span className={`text-xs px-2 py-0.5 rounded-full border ${getNodeBadgeColor(nodeAssessment.security_status, nodeAssessment.security_status)}`}>
                              {nodeAssessment.security_status || "NOT ASSESSED"}
                            </span>
                            {nodeAssessment.mitre_stage && (
                              <Badge variant="outline" className="border-indigo-300 text-indigo-700 dark:text-indigo-300">
                                MITRE: {nodeAssessment.mitre_stage}
                              </Badge>
                            )}
                          </div>
                        </div>

                        <div className="text-right">
                          <div className="text-slate-500">Attack Probability</div>
                          <div className="text-base font-bold font-mono text-slate-900 dark:text-slate-100">
                            {((nodeAssessment.attack_probability || 0) * 100).toFixed(1)}%
                          </div>
                        </div>
                      </div>

                      {/* Explanation box */}
                      <div className="rounded-lg border border-slate-200 bg-slate-50/50 p-3 text-xs dark:border-slate-800 dark:bg-slate-800/30 leading-relaxed">
                        <div className="font-semibold text-slate-800 dark:text-slate-200 mb-1 flex items-center gap-1.5">
                          <Info className="h-3.5 w-3.5 text-indigo-500" />
                          Evaluation Rationale:
                        </div>
                        <p className="text-slate-600 dark:text-slate-400">
                          {nodeAssessment.explanation || "No assessment explanation available."}
                        </p>
                      </div>

                      {/* Top contributing indicators */}
                      {nodeAssessment.top_indicators && nodeAssessment.top_indicators.length > 0 && (
                        <div>
                          <span className="text-slate-500 font-medium block mb-1.5">Top Feature Indicators & Evidence:</span>
                          <div className="space-y-1">
                            {nodeAssessment.top_indicators.map((ind, i) => (
                              <div
                                key={createEntityKey("dlg-ind", `${selectedNode?.id || "node"}-${i}`, [ind])}
                                className="flex items-start gap-2 p-2 rounded-md border border-slate-200 bg-slate-50 dark:border-slate-800 dark:bg-slate-800/40"
                              >
                                <Crosshair className="h-3.5 w-3.5 text-indigo-500 shrink-0 mt-0.5" />
                                <span className="text-slate-700 dark:text-slate-300">{ind}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {nodeAssessment.mitre_technique && (
                        <div className="flex items-center gap-2 p-2.5 rounded-lg border border-indigo-200 bg-indigo-50/50 dark:border-indigo-950 dark:bg-indigo-950/20 text-indigo-950 dark:text-indigo-200 text-xs font-mono">
                          <Shield className="h-4 w-4 text-indigo-600 shrink-0" />
                          <span>MITRE Technique: {nodeAssessment.mitre_technique}</span>
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="p-6 text-center text-slate-500">
                      No threat assessment available.
                    </div>
                  )}
                </TabsContent>
              </Tabs>

              <div className="flex flex-wrap items-center justify-between gap-2 pt-3 border-t border-slate-200 dark:border-slate-800">
                <div className="flex items-center gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={handleRunThreatAssessment}
                    disabled={loadingNodeAssessment}
                    className="gap-1.5 text-xs"
                  >
                    <RefreshCw className={`h-3.5 w-3.5 ${loadingNodeAssessment ? "animate-spin" : ""}`} />
                    Re-evaluate
                  </Button>

                  {selectedNode && (
                    <Button
                      size="sm"
                      variant={connectedDevice?.ip === selectedNode.ip ? "secondary" : "default"}
                      disabled={connectingNodeId === selectedNode.id || connectedDevice?.ip === selectedNode.ip}
                      onClick={() => handleConnectNodeAsActive(selectedNode)}
                      className={
                        connectedDevice?.ip === selectedNode.ip
                          ? "h-8 text-xs bg-emerald-600/20 text-emerald-600 border border-emerald-500/40"
                          : "h-8 text-xs bg-emerald-600 hover:bg-emerald-700 text-white font-semibold gap-1.5 shadow-sm"
                      }
                    >
                      <Wifi className="h-3.5 w-3.5" />
                      {connectedDevice?.ip === selectedNode.ip ? "Active Monitored Device" : "Connect & Monitor"}
                    </Button>
                  )}
                </div>

                <div className="flex gap-2">
                  <Button variant="outline" size="sm" onClick={() => setSelectedNode(null)}>
                    Close
                  </Button>
                  {onNavigateToTraffic && (
                    <Button
                      size="sm"
                      className="bg-indigo-600 hover:bg-indigo-700 text-white gap-1"
                      onClick={() => {
                        setSelectedNode(null)
                        onNavigateToTraffic()
                      }}
                    >
                      Inspect Packets
                      <ChevronRight className="h-3.5 w-3.5" />
                    </Button>
                  )}
                </div>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
