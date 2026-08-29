"use client"

import { useEffect, useState } from "react"
import { Activity, BrainCircuit, Database, Network, SearchCheck, ShieldAlert } from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  getPacketStatistics,
  getThreatHunt,
  healthCheck,
  startPacketCapture,
  type HealthCheckResponse,
  type PacketStatistics,
  type StartCaptureResponse,
  type Threat,
  type ThreatHuntResponse,
} from "@/lib/api"

const progressItems = [
  {
    title: "Network packet capture",
    value: 60,
    note: "Already mostly working. Stabilize reliable collection first.",
    icon: Activity,
  },
  {
    title: "Flow-level feature extraction",
    value: 20,
    note: "Turn grouped connections into model-ready numbers.",
    icon: Network,
  },
  {
    title: "Packet-level feature extraction",
    value: 40,
    note: "Convert packet fields like size, flags, and timing into features.",
    icon: SearchCheck,
  },
  {
    title: "Dataset preprocessing",
    value: 10,
    note: "Clean, normalize, and split training data.",
    icon: Database,
  },
  {
    title: "Model training pipeline",
    value: 0,
    note: "No training automation is in place yet.",
    icon: BrainCircuit,
  },
  {
    title: "XAI / SHAP / attention",
    value: 0,
    note: "Explanations still need to be added after model training.",
    icon: ShieldAlert,
  },
]

const workQueue = [
  "Finish and harden packet capture so repeated runs are reliable.",
  "Group captured packets into flows by source, destination, port, and time window.",
  "Extract flow-level features such as duration, total bytes, and packet count.",
  "Extract packet-level features such as packet size, TCP flags, TTL, and timing gaps.",
  "Clean missing values, remove broken rows, and normalize numeric fields.",
  "Split the dataset into training and testing files that the model can reuse.",
  "Build the training script and save model weights.",
  "Add explainability output as simple JSON for the frontend.",
]

const builtNow = [
  "Scapy packet capture and packet normalization already exist in the backend.",
  "Packet statistics are already exposed through the API.",
  "Threat hunting and behavior-based threat detection are already implemented.",
  "The ML dataset, training pipeline, saved weights, and explainability pipeline are still missing.",
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

function formatThreatTitle(threat?: Threat | null) {
  if (!threat) {
    return "No active finding yet"
  }

  return threat.type.replace(/_/g, " ").replace(/\b\w/g, (match) => match.toUpperCase())
}

export default function HomePage() {
  const [healthData, setHealthData] = useState<HealthCheckResponse | null>(null)
  const [packetStats, setPacketStats] = useState<PacketStatistics | null>(null)
  const [huntData, setHuntData] = useState<ThreatHuntResponse | null>(null)
  const [lastCapture, setLastCapture] = useState<StartCaptureResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [capturing, setCapturing] = useState(false)
  const [error, setError] = useState("")

  const refreshData = async () => {
    try {
      const [health, packetStatistics, hunt] = await Promise.all([
        healthCheck(),
        getPacketStatistics(),
        getThreatHunt(3),
      ])

      setHealthData(health)
      setPacketStats(packetStatistics)
      setHuntData(hunt)
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
      const result = await startPacketCapture(0, 10)
      setLastCapture(result)
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

  return (
    <main className="min-h-screen bg-[radial-gradient(circle_at_top,_rgba(14,165,233,0.08),_transparent_35%),linear-gradient(180deg,_rgba(255,255,255,0.9),_rgba(241,245,249,1))] px-4 py-6 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-7xl space-y-6">
        <section className="overflow-hidden rounded-[28px] border border-slate-200 bg-slate-950 text-white shadow-xl shadow-slate-300/30">
          <div className="grid gap-6 px-6 py-8 sm:px-8 lg:grid-cols-[1.5fr_0.9fr] lg:px-10">
            <div className="space-y-4">
              <Badge className="bg-cyan-400/15 text-cyan-200 hover:bg-cyan-400/15">Focused frontend for your task</Badge>
              <div className="space-y-3">
                <h1 className="max-w-3xl text-3xl font-semibold tracking-tight sm:text-4xl">
                  Malware Detection Project Workbench
                </h1>
                <p className="max-w-2xl text-sm leading-6 text-slate-300 sm:text-base">
                  This screen now shows only the parts that matter for your current work: capture readiness,
                  feature extraction progress, training pipeline status, and live findings from the backend.
                </p>
              </div>
            </div>

            <div className="grid gap-3 rounded-3xl border border-white/10 bg-white/5 p-4 sm:grid-cols-2 lg:grid-cols-1">
              <div className="rounded-2xl bg-white/10 p-4">
                <p className="text-xs uppercase tracking-[0.2em] text-slate-300">Backend</p>
                <p className="mt-2 text-2xl font-semibold">
                  {healthData?.status === "healthy" ? "Healthy" : loading ? "Loading" : "Offline"}
                </p>
                <p className="mt-1 text-xs text-slate-300">{formatTimestamp(healthData?.timestamp)}</p>
              </div>
              <div className="rounded-2xl bg-white/10 p-4">
                <p className="text-xs uppercase tracking-[0.2em] text-slate-300">Packets Stored</p>
                <p className="mt-2 text-2xl font-semibold">{packetStats?.stored_packets ?? 0}</p>
                <p className="mt-1 text-xs text-slate-300">
                  Total captured: {packetStats?.total_packets ?? 0}
                </p>
              </div>
            </div>
          </div>
        </section>

        {error && (
          <section className="rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
            {error}
          </section>
        )}

        <section className="grid gap-4 xl:grid-cols-[1.45fr_0.95fr]">
          <Card className="border-slate-200 shadow-sm">
            <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <CardTitle>Progress by Work Block</CardTitle>
                <CardDescription>
                  These are the exact work areas from your task image, shown as separate blocks.
                </CardDescription>
              </div>
              <Button variant="outline" onClick={refreshData}>
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
              <CardTitle>Live Capture Block</CardTitle>
              <CardDescription>
                Use this while testing packet capture and watching the backend react.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-1">
                <div className="rounded-2xl bg-slate-50 p-4">
                  <p className="text-xs uppercase tracking-wide text-slate-500">Latest hunt result</p>
                  <p className="mt-2 text-base font-semibold text-slate-900">
                    {formatThreatTitle(huntData?.best_finding)}
                  </p>
                  <p className="mt-1 text-sm text-slate-600">
                    Confirmed: {huntData?.confirmed_findings ?? 0} | Leads: {huntData?.suspicious_leads ?? 0}
                  </p>
                </div>
                <div className="rounded-2xl bg-slate-50 p-4">
                  <p className="text-xs uppercase tracking-wide text-slate-500">Average packet size</p>
                  <p className="mt-2 text-base font-semibold text-slate-900">
                    {packetStats?.average_packet_size ? `${packetStats.average_packet_size.toFixed(1)} bytes` : "No data yet"}
                  </p>
                  <p className="mt-1 text-sm text-slate-600">
                    Protocol groups: {Object.keys(packetStats?.protocols ?? {}).length}
                  </p>
                </div>
              </div>

              <div className="rounded-3xl border border-slate-200 bg-white p-4">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <div>
                    <p className="text-sm font-medium text-slate-900">Manual 10-second capture</p>
                    <p className="text-xs text-slate-600">
                      Start capture, then open or reload the website you want to observe.
                    </p>
                  </div>
                  <Button onClick={handleCapture} disabled={capturing}>
                    {capturing ? "Capturing..." : "Capture 10s"}
                  </Button>
                </div>
                <div className="mt-3 rounded-2xl bg-slate-50 p-3 text-sm text-slate-700">
                  {lastCapture
                    ? `Last run captured ${lastCapture.packets_captured} packet(s) on ${lastCapture.interface}.`
                    : "No manual capture has been triggered from the frontend yet."}
                </div>
              </div>
            </CardContent>
          </Card>
        </section>

        <section className="grid gap-4 lg:grid-cols-3">
          <Card className="border-slate-200 shadow-sm lg:col-span-2">
            <CardHeader>
              <CardTitle>Work Queue</CardTitle>
              <CardDescription>
                The implementation path is laid out in order so you can work block by block.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid gap-3">
                {workQueue.map((step, index) => (
                  <div key={step} className="flex gap-3 rounded-2xl border border-slate-200 bg-slate-50 p-3">
                    <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-slate-900 text-sm font-semibold text-white">
                      {index + 1}
                    </div>
                    <p className="pt-1 text-sm leading-6 text-slate-700">{step}</p>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card className="border-slate-200 shadow-sm">
            <CardHeader>
              <CardTitle>Current Backend Readiness</CardTitle>
              <CardDescription>
                What already exists versus what still needs to be built.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {builtNow.map((item) => (
                <div key={item} className="rounded-2xl bg-slate-50 p-3 text-sm leading-6 text-slate-700">
                  {item}
                </div>
              ))}
            </CardContent>
          </Card>
        </section>

        <section className="grid gap-4 lg:grid-cols-2">
          <Card className="border-slate-200 shadow-sm">
            <CardHeader>
              <CardTitle>Best Finding Block</CardTitle>
              <CardDescription>
                This is the clearest live security signal the backend can currently explain.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="rounded-3xl border border-slate-200 bg-slate-50 p-4">
                <div className="flex items-center justify-between gap-3">
                  <p className="text-base font-semibold text-slate-900">
                    {formatThreatTitle(huntData?.best_finding)}
                  </p>
                  {huntData?.best_finding?.severity && <Badge>{huntData.best_finding.severity}</Badge>}
                </div>
                <p className="mt-2 text-sm leading-6 text-slate-700">
                  {huntData?.best_finding?.description ?? "Run capture and generate traffic to surface a finding here."}
                </p>
                <p className="mt-3 text-xs text-slate-500">
                  Last update: {formatTimestamp(huntData?.timestamp)}
                </p>
              </div>
            </CardContent>
          </Card>

          <Card className="border-slate-200 shadow-sm">
            <CardHeader>
              <CardTitle>Why This Frontend Exists</CardTitle>
              <CardDescription>
                A narrow UI helps you validate only the pieces needed for your task.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3 text-sm leading-6 text-slate-700">
              <div className="rounded-2xl bg-slate-50 p-4">
                It keeps packet capture, feature engineering, training readiness, and explainability progress visible in one place.
              </div>
              <div className="rounded-2xl bg-slate-50 p-4">
                It removes unrelated admin and marketing screens, so you can test the exact parts you are building.
              </div>
              <div className="rounded-2xl bg-slate-50 p-4">
                When the ML pipeline is added, this page is ready to grow into dataset, training, and explanation blocks instead of a full redesign.
              </div>
            </CardContent>
          </Card>
        </section>
      </div>
    </main>
  )
}
