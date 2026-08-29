"use client"

import { useEffect, useState } from "react"
import { Activity, BrainCircuit, Database, Network, RefreshCw, SearchCheck, ShieldAlert } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import {
  getPackets,
  getPacketStatistics,
  getTrafficByProtocol,
  healthCheck,
  startPacketCapture,
  type HealthCheckResponse,
  type Packet,
  type PacketStatistics,
  type StartCaptureResponse,
  type TrafficProtocolResponse,
} from "@/lib/api"

const progressItems = [
  {
    title: "Network packet capture",
    value: 93,
    note: "Stabilize the Scapy capture path first.",
    icon: Activity,
  },
  {
    title: "Flow-level feature extraction",
    value: 20,
    note: "Build flow grouping and aggregated flow features.",
    icon: Network,
  },
  {
    title: "Packet-level feature extraction",
    value: 40,
    note: "Turn packet fields into model features.",
    icon: SearchCheck,
  },
  {
    title: "Dataset preprocessing",
    value: 10,
    note: "Clean, normalize, and split the dataset.",
    icon: Database,
  },
  {
    title: "Model training pipeline",
    value: 0,
    note: "Training automation still needs to be added.",
    icon: BrainCircuit,
  },
  {
    title: "XAI / SHAP / attention",
    value: 0,
    note: "Explanation outputs are not built yet.",
    icon: ShieldAlert,
  },
]

function getProgressTone(value: number) {
  if (value >= 50) {
    return "bg-emerald-500"
  }

  if (value > 0) {
    return "bg-amber-500"
  }

  return "bg-slate-300"
}

function formatTimestamp(value?: string) {
  if (!value) {
    return "No recent update"
  }

  return new Date(value).toLocaleString()
}

function formatPacketEndpoint(value?: string | null) {
  return value && value.trim() ? value : "Unknown"
}

function formatPacketTypeName(name: string) {
  return name.replace(/_/g, " ")
}

function getTopProtocols(protocols?: TrafficProtocolResponse["protocols"]) {
  return Object.entries(protocols || {})
    .sort(([, left], [, right]) => right.count - left.count)
    .slice(0, 6)
}

export default function HomePage() {
  const [healthData, setHealthData] = useState<HealthCheckResponse | null>(null)
  const [packetStats, setPacketStats] = useState<PacketStatistics | null>(null)
  const [packets, setPackets] = useState<Packet[]>([])
  const [protocolData, setProtocolData] = useState<TrafficProtocolResponse | null>(null)
  const [lastCapture, setLastCapture] = useState<StartCaptureResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [capturing, setCapturing] = useState(false)
  const [error, setError] = useState("")

  const refreshData = async () => {
    try {
      const [health, packetStatistics, packetList, protocols] = await Promise.all([
        healthCheck(),
        getPacketStatistics(),
        getPackets(20, 0),
        getTrafficByProtocol(),
      ])

      setHealthData(health)
      setPacketStats(packetStatistics)
      setPackets(packetList.packets || [])
      setProtocolData(protocols)
      setError("")
    } catch (err) {
      console.error("Failed to refresh workbench data:", err)
      setError("Unable to reach the backend right now. Start the backend and try again.")
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    refreshData()
    const interval = setInterval(refreshData, 5000)
    return () => clearInterval(interval)
  }, [])

  const handleCapture = async () => {
    setCapturing(true)
    setError("")

    try {
      const result = await startPacketCapture(0, 5)
      setLastCapture(result)
      if (result.status === "unavailable") {
        setError(result.message || "Packet capture is unavailable on this machine.")
        return
      }
      await refreshData()
    } catch (err) {
      console.error("Packet capture failed:", err)
      const message =
        err instanceof Error ? err.message : "Packet capture failed. Check backend permissions and try again."
      setError(message)
    } finally {
      setCapturing(false)
    }
  }

  const topProtocols = getTopProtocols(protocolData?.protocols)

  return (
    <main className="min-h-screen bg-[radial-gradient(circle_at_top,_rgba(14,165,233,0.08),_transparent_35%),linear-gradient(180deg,_rgba(255,255,255,0.9),_rgba(241,245,249,1))] px-4 py-6 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-7xl space-y-6">
        <section className="overflow-hidden rounded-[28px] border border-slate-200 bg-slate-950 text-white shadow-xl shadow-slate-300/30">
          <div className="grid gap-6 px-6 py-8 sm:px-8 lg:grid-cols-[1.4fr_1fr] lg:px-10">
            <div className="space-y-4">
              <Badge className="bg-cyan-400/15 text-cyan-200 hover:bg-cyan-400/15">Task-focused frontend</Badge>
              <div className="space-y-3">
                <h1 className="max-w-3xl text-3xl font-semibold tracking-tight sm:text-4xl">
                  Packet Capture and Inspection Workbench
                </h1>
                <p className="max-w-2xl text-sm leading-6 text-slate-300 sm:text-base">
                  This view is stripped down to the parts you need right now: task progress, 5-second capture,
                  packet inspection, and packet-type visibility.
                </p>
              </div>
            </div>

            <div className="grid gap-3 rounded-3xl border border-white/10 bg-white/5 p-4 sm:grid-cols-2">
              <div className="rounded-2xl bg-white/10 p-4">
                <p className="text-xs uppercase tracking-[0.2em] text-slate-300">Backend</p>
                <p className="mt-2 text-2xl font-semibold">
                  {healthData?.status === "healthy" ? "Healthy" : loading ? "Loading" : "Offline"}
                </p>
                <p className="mt-1 text-xs text-slate-300">{formatTimestamp(healthData?.timestamp)}</p>
              </div>
              <div className="rounded-2xl bg-white/10 p-4">
                <p className="text-xs uppercase tracking-[0.2em] text-slate-300">Stored packets</p>
                <p className="mt-2 text-2xl font-semibold">{packetStats?.stored_packets ?? 0}</p>
                <p className="mt-1 text-xs text-slate-300">Total seen: {packetStats?.total_packets ?? 0}</p>
              </div>
            </div>
          </div>
        </section>

        {error && (
          <section className="rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
            {error}
          </section>
        )}

        <section className="grid gap-4 xl:grid-cols-[1.25fr_0.75fr]">
          <Card className="border-slate-200 shadow-sm">
            <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <CardTitle>Progress by Work Block</CardTitle>
                <CardDescription>
                  The active development areas from your task image.
                </CardDescription>
              </div>
              <Button variant="outline" onClick={refreshData}>
                <RefreshCw className="mr-2 h-4 w-4" />
                Refresh
              </Button>
            </CardHeader>
            <CardContent className="grid gap-4 md:grid-cols-2">
              {progressItems.map((item) => (
                <div key={item.title} className="rounded-3xl border border-slate-200 bg-slate-50 p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <p className="text-sm font-medium text-slate-900">{item.title}</p>
                      <p className="text-xs leading-5 text-slate-600">{item.note}</p>
                    </div>
                    <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-white shadow-sm">
                      <item.icon className="h-5 w-5 text-slate-700" />
                    </div>
                  </div>
                  <div className="mt-4 space-y-2">
                    <div className="flex items-center justify-between text-xs text-slate-600">
                      <span>Completion</span>
                      <span>{item.value}%</span>
                    </div>
                    <div className="h-2.5 overflow-hidden rounded-full bg-slate-200">
                      <div className={`h-full rounded-full ${getProgressTone(item.value)}`} style={{ width: `${item.value}%` }} />
                    </div>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>

          <Card className="border-slate-200 shadow-sm">
            <CardHeader>
              <CardTitle>Packet Capture</CardTitle>
              <CardDescription>
                Trigger a short capture window and inspect what came in.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="rounded-3xl border border-slate-200 bg-slate-50 p-4">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <div>
                    <p className="text-sm font-medium text-slate-900">Manual 5-second capture</p>
                    <p className="text-xs text-slate-600">
                      Start capture, then open or reload the site or app traffic you want to inspect.
                    </p>
                  </div>
                  <Button onClick={handleCapture} disabled={capturing}>
                    {capturing ? "Capturing..." : "Capture 5s"}
                  </Button>
                </div>
                <div className="mt-3 rounded-2xl bg-white p-3 text-sm text-slate-700">
                  {lastCapture
                    ? `Last run captured ${lastCapture.packets_captured} packet(s) on ${lastCapture.interface}.`
                    : "No manual capture has been triggered from the frontend yet."}
                </div>
              </div>

              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-1">
                <div className="rounded-2xl bg-slate-50 p-4">
                  <p className="text-xs uppercase tracking-wide text-slate-500">Average packet size</p>
                  <p className="mt-2 text-base font-semibold text-slate-900">
                    {packetStats?.average_packet_size ? `${packetStats.average_packet_size.toFixed(1)} bytes` : "No data yet"}
                  </p>
                </div>
                <div className="rounded-2xl bg-slate-50 p-4">
                  <p className="text-xs uppercase tracking-wide text-slate-500">Last update</p>
                  <p className="mt-2 text-base font-semibold text-slate-900">
                    {formatTimestamp(healthData?.timestamp)}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </section>

        <section className="grid gap-4 xl:grid-cols-[0.9fr_1.1fr]">
          <Card className="border-slate-200 shadow-sm">
            <CardHeader>
              <CardTitle>Packet Types</CardTitle>
              <CardDescription>
                A quick view of what kinds of traffic are currently being captured.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {topProtocols.length === 0 ? (
                <div className="rounded-2xl bg-slate-50 p-4 text-sm text-slate-600">
                  No protocol data yet. Run a capture to populate this section.
                </div>
              ) : (
                topProtocols.map(([protocol, info]) => (
                  <div key={protocol} className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <div className="flex items-center justify-between gap-3">
                      <p className="text-sm font-medium text-slate-900">{formatPacketTypeName(protocol)}</p>
                      <Badge variant="secondary">{info.percentage}%</Badge>
                    </div>
                    <p className="mt-2 text-sm text-slate-700">
                      {info.count} packet(s) captured
                    </p>
                    <div className="mt-3 h-2 overflow-hidden rounded-full bg-slate-200">
                      <div className="h-full rounded-full bg-cyan-500" style={{ width: `${Math.min(info.percentage, 100)}%` }} />
                    </div>
                  </div>
                ))
              )}
            </CardContent>
          </Card>

          <Card className="border-slate-200 shadow-sm">
            <CardHeader>
              <CardTitle>Packet Inspection</CardTitle>
              <CardDescription>
                Recent packets with source, destination, protocol, size, and packet details.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {packets.length === 0 ? (
                <div className="rounded-2xl bg-slate-50 p-4 text-sm text-slate-600">
                  No packets available yet. Run a capture and this section will fill in.
                </div>
              ) : (
                packets.map((packet, index) => (
                  <div key={`${packet.timestamp}-${index}`} className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge>{packet.protocol}</Badge>
                      {packet.application_protocol && <Badge variant="secondary">{packet.application_protocol}</Badge>}
                      {packet.dest_port && <Badge variant="outline">Port {packet.dest_port}</Badge>}
                    </div>
                    <p className="text-xs text-slate-500">{formatTimestamp(packet.timestamp)}</p>
                    </div>

                    <div className="mt-3 grid gap-3 md:grid-cols-2">
                      <div className="rounded-xl bg-white p-3">
                        <p className="text-[11px] uppercase tracking-wide text-slate-500">Source</p>
                        <p className="mt-1 break-all text-sm font-medium text-slate-900">
                          {formatPacketEndpoint(packet.source_ip)}
                        </p>
                      </div>
                      <div className="rounded-xl bg-white p-3">
                        <p className="text-[11px] uppercase tracking-wide text-slate-500">Destination</p>
                        <p className="mt-1 break-all text-sm font-medium text-slate-900">
                          {formatPacketEndpoint(packet.dest_ip || packet.observed_host || packet.dns_query)}
                        </p>
                      </div>
                    </div>

                    <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                      <div className="rounded-xl bg-white p-3">
                        <p className="text-[11px] uppercase tracking-wide text-slate-500">Size</p>
                        <p className="mt-1 text-sm font-medium text-slate-900">{packet.size_bytes} bytes</p>
                      </div>
                      <div className="rounded-xl bg-white p-3">
                        <p className="text-[11px] uppercase tracking-wide text-slate-500">Flags</p>
                        <p className="mt-1 text-sm font-medium text-slate-900">
                          {packet.flags && packet.flags.length > 0 ? packet.flags.join(", ") : "None"}
                        </p>
                      </div>
                      <div className="rounded-xl bg-white p-3">
                        <p className="text-[11px] uppercase tracking-wide text-slate-500">DNS query</p>
                        <p className="mt-1 break-all text-sm font-medium text-slate-900">
                          {packet.dns_query || "None"}
                        </p>
                      </div>
                      <div className="rounded-xl bg-white p-3">
                        <p className="text-[11px] uppercase tracking-wide text-slate-500">Security Alerts</p>
                        <p className="mt-1 text-sm font-medium text-red-600">
                          {packet.security_alerts && packet.security_alerts.length > 0
                            ? packet.security_alerts.join(", ")
                            : "None"}
                        </p>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </CardContent>
          </Card>
        </section>
      </div>
    </main>
  )
}
