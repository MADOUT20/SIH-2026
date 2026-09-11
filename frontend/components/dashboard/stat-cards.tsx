"use client"
// Overview cards that surface the main packet and threat counts.

import { useEffect, useState } from "react"
import { Activity, ShieldAlert, Server, Workflow, Laptop, ShieldCheck, Wifi } from "lucide-react"
import { Card, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { getAdminDashboard, getTrafficSummary } from "@/lib/api"
import { useDevice } from "@/context/device-context"

interface HealthData {
  status?: string
  timestamp?: string
}

interface StatCardsProps {
  healthData?: HealthData | null
}

function formatCount(value: number) {
  return value.toLocaleString()
}

function formatTimestamp(timestamp?: string) {
  if (!timestamp) {
    return "Awaiting update"
  }

  return new Date(timestamp).toLocaleTimeString()
}

export function StatCards({ healthData }: StatCardsProps) {
  const { connectedDevice, activeTraffic, activeAssessment, isMonitoring } = useDevice()
  const [overview, setOverview] = useState({
    total_packets: 0,
    total_threats: 0,
    medium_threats: 0,
    high_alert_threats: 0,
    critical_threats: 0,
    last_update: "",
  })
  const [connections, setConnections] = useState(0)

  useEffect(() => {
    let isMounted = true
    const fetchOverview = async () => {
      try {
        const [dashboard, trafficSummary] = await Promise.all([
          getAdminDashboard(),
          getTrafficSummary(),
        ])

        if (isMounted) {
          setOverview({
            total_packets: dashboard.total_packets || 0,
            total_threats: dashboard.total_threats || 0,
            medium_threats: dashboard.medium_threats || 0,
            high_alert_threats: dashboard.high_alert_threats || 0,
            critical_threats: dashboard.critical_threats || 0,
            last_update: dashboard.last_update || "",
          })
          setConnections(trafficSummary.connections?.unique_connections || 0)
        }
      } catch (error) {
        if (isMounted) console.error("Failed to fetch overview stats:", error)
      }
    }

    fetchOverview()
    const interval = setInterval(fetchOverview, 5000)
    return () => {
      isMounted = false
      clearInterval(interval)
    }
  }, [])

  // If a device is actively connected, show device-scoped cards
  if (isMonitoring && connectedDevice) {
    const devPackets = activeTraffic?.packet_count ?? (connectedDevice as any).packet_count ?? 0
    const devBytes = activeTraffic?.byte_count ?? (connectedDevice as any).total_bytes ?? 0
    const devSecurity = activeAssessment?.security_status ?? (connectedDevice as any).security_status ?? "NOT ASSESSED"
    const devAttackProb = Math.round((activeAssessment?.attack_probability ?? (connectedDevice as any).attack_probability ?? 0) * 100)
    const connCount = activeTraffic?.connections?.length ?? 0

    const isMalicious = devSecurity.includes("MALICIOUS") || devSecurity.includes("HIGH RISK")
    const isSuspicious = devSecurity.includes("SUSPICIOUS")

    const deviceStats = [
      {
        label: "Monitored Target Packets",
        value: formatCount(devPackets),
        change: devBytes > 0 ? `${(devBytes / 1024).toFixed(1)} KB captured` : "Awaiting observed flows",
        changeType: devPackets > 0 ? ("positive" as const) : ("neutral" as const),
        icon: Activity,
        description: `Scoped to ${connectedDevice.name}`,
      },
      {
        label: "Device Threat Status",
        value: devSecurity,
        change: devSecurity === "NOT ASSESSED" ? "Insufficient traffic data" : `${devAttackProb}% attack score`,
        changeType: isMalicious ? ("negative" as const) : isSuspicious ? ("neutral" as const) : ("positive" as const),
        icon: isMalicious ? ShieldAlert : ShieldCheck,
        description: activeAssessment?.mitre_stage ? `MITRE: ${activeAssessment.mitre_stage}` : "PyTorch LSTM Assessment",
      },
      {
        label: "Observed Endpoints",
        value: formatCount(connCount),
        change: `${activeTraffic?.ports?.length ?? 0} active port(s)`,
        changeType: "neutral" as const,
        icon: Workflow,
        description: `Direct socket peer links`,
      },
      {
        label: "Target Connectivity",
        value: "MONITORING ACTIVE",
        change: `IP: ${connectedDevice.ip}`,
        changeType: "positive" as const,
        icon: Laptop,
        description: connectedDevice.device_type || "Endpoint",
      },
    ]

    return (
      <div className="space-y-2">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {deviceStats.map((stat) => (
            <Card key={stat.label} className="bg-card border-indigo-500/20 dark:border-indigo-500/30">
              <CardContent className="p-5">
                <div className="flex items-center justify-between">
                  <div className="space-y-1">
                    <p className="text-sm text-muted-foreground">{stat.label}</p>
                    <p className="text-2xl font-bold text-foreground truncate max-w-[200px]" title={stat.value}>{stat.value}</p>
                  </div>
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-indigo-500/10 text-indigo-500 dark:text-indigo-400">
                    <stat.icon className="h-5 w-5" />
                  </div>
                </div>
                <div className="mt-3 flex items-center justify-between gap-2">
                  <span
                    className={`text-xs font-medium truncate ${
                      stat.changeType === "positive"
                        ? "text-emerald-500"
                        : stat.changeType === "negative"
                          ? "text-red-500"
                          : "text-muted-foreground"
                    }`}
                  >
                    {stat.change}
                  </span>
                  <span className="text-[11px] text-muted-foreground truncate">{stat.description}</span>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    )
  }

  const stats = [
    {
      label: "Packets Captured",
      value: formatCount(overview.total_packets),
      change: formatTimestamp(overview.last_update),
      changeType: "positive" as const,
      icon: Activity,
      description: "Last backend sync",
    },
    {
      label: "Threats Detected",
      value: formatCount(overview.total_threats),
      change: `${overview.high_alert_threats} high alert, ${overview.medium_threats} medium`,
      changeType: overview.high_alert_threats > 0 ? ("negative" as const) : overview.medium_threats > 0 ? ("neutral" as const) : ("positive" as const),
      icon: ShieldAlert,
      description: "Medium and above",
    },
    {
      label: "Network Connections",
      value: formatCount(connections),
      change: "Live topology",
      changeType: "neutral" as const,
      icon: Workflow,
      description: "Unique source-destination pairs",
    },
    {
      label: "Backend Status",
      value: healthData?.status === "healthy" ? "Healthy" : "Unhealthy",
      change: formatTimestamp(healthData?.timestamp),
      changeType: healthData?.status === "healthy" ? ("positive" as const) : ("negative" as const),
      icon: Server,
      description: "Last health check",
    },
  ]

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      {stats.map((stat) => (
        <Card key={stat.label} className="bg-card border-border">
          <CardContent className="p-5">
            <div className="flex items-center justify-between">
              <div className="space-y-1">
                <p className="text-sm text-muted-foreground">{stat.label}</p>
                <p className="text-2xl font-bold text-foreground">{stat.value}</p>
              </div>
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                <stat.icon className="h-5 w-5 text-primary" />
              </div>
            </div>
            <div className="mt-3 flex items-center gap-2">
              <span
                className={`text-xs font-medium ${
                  stat.changeType === "positive"
                    ? "text-emerald-500"
                    : stat.changeType === "negative"
                      ? "text-red-500"
                      : "text-muted-foreground"
                }`}
              >
                {stat.change}
              </span>
              <span className="text-xs text-muted-foreground">{stat.description}</span>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  )
}
