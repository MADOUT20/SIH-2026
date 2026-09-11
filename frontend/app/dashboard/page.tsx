"use client"

import { useState, useEffect } from "react"
import { healthCheck, type HealthCheckResponse } from "../../lib/api"
import { DashboardSidebar } from "@/components/dashboard/dashboard-sidebar"
import { DashboardHeader } from "@/components/dashboard/dashboard-header"
import { StatCards } from "@/components/dashboard/stat-cards"
import { TrafficChartPanel, PacketInspectionPanel, TrafficAnalysisPanel } from "@/components/dashboard/traffic"
import { BlockedSitesCard, ObservedDevicesCard, ThreatDetectionPanel } from "@/components/dashboard/threats"
import { SettingsPanel, AdminPanel, ActionLogs } from "@/components/dashboard/admin"
import { AlertNotifications, NotificationArchive } from "@/components/dashboard/alerts"
import { MitreAttackMatrix } from "@/components/dashboard/mitre-matrix"
import { WebsiteThreatScanner } from "@/components/dashboard/website-scanner"
import { MLBenchmarkPanel } from "@/components/dashboard/ml-benchmark"
import { AttackForecastingPanel } from "@/components/dashboard/forecasting"
import { NetworkTopologyPanel } from "@/components/dashboard/network-topology"
import WorkbenchPage from "@/app/workbench/page"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { 
  BrainCircuit, 
  TrendingUp, 
  Network, 
  Layers, 
  Activity, 
  ArrowRight,
  Radio
} from "lucide-react"

export default function DashboardPage() {
  const [activeTab, setActiveTab] = useState("overview")
  const [healthData, setHealthData] = useState<HealthCheckResponse | null>(null)
  const [mobileNavOpen, setMobileNavOpen] = useState(false)

  useEffect(() => {
    let isMounted = true
    const fetchHealthData = async () => {
      try {
        const data = await healthCheck()
        if (isMounted) setHealthData(data)
      } catch (error) {
        if (isMounted) console.error("Failed to fetch health status:", error)
      }
    }

    fetchHealthData()
    return () => {
      isMounted = false
    }
  }, [])

  return (
    <div className="flex h-screen w-full overflow-hidden bg-background">
      <DashboardSidebar
        activeTab={activeTab}
        onTabChange={setActiveTab}
        mobileOpen={mobileNavOpen}
        onMobileOpenChange={setMobileNavOpen}
      />
      <div className="flex flex-1 flex-col h-full min-w-0 overflow-hidden">
        <DashboardHeader
          activeTab={activeTab}
          onTabChange={setActiveTab}
          onMenuClick={() => setMobileNavOpen(true)}
        />
        <main className="flex-1 space-y-6 overflow-y-auto overflow-x-hidden min-h-0 p-4 sm:p-6">
          {/* ========================================================= */}
          {/* 1. OVERVIEW — HIGH-LEVEL SOC DASHBOARD (BALANCED LAYOUT)   */}
          {/* ========================================================= */}
          {activeTab === "overview" && (
            <>
              {/* Row 1: High-level SOC Stat Cards */}
              <StatCards healthData={healthData} />

              {/* Row 2: High-Level SOC Summary Cards Grid */}
              <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
                {/* SOC Quick Navigation & Status Tile */}
                <Card className="border-border bg-gradient-to-br from-slate-900 to-indigo-950 text-white shadow-md flex flex-col justify-between">
                  <CardHeader className="pb-2">
                    <div className="flex items-center justify-between">
                      <Badge className="bg-indigo-600 text-white text-[10px]">SOC Core Modules</Badge>
                      <span className="flex h-2 w-2 relative">
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                        <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                      </span>
                    </div>
                    <CardTitle className="text-base font-bold text-white flex items-center gap-2 mt-2">
                      <Radio className="w-4 h-4 text-sky-400" />
                      Live Threat Monitoring Engine
                    </CardTitle>
                    <CardDescription className="text-xs text-slate-300">
                      Multi-vector behavioral analysis active across physical adapter interfaces and connected endpoints.
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="pt-2 space-y-2">
                    <div className="grid grid-cols-2 gap-2 text-xs">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => setActiveTab("topology")}
                        className="h-8 justify-start text-xs border-slate-700 bg-slate-800/80 text-slate-200 hover:bg-slate-700 hover:text-white"
                      >
                        <Network className="w-3.5 h-3.5 mr-1.5 text-sky-400" />
                        Topology Map
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => setActiveTab("forecasting")}
                        className="h-8 justify-start text-xs border-slate-700 bg-slate-800/80 text-slate-200 hover:bg-slate-700 hover:text-white"
                      >
                        <TrendingUp className="w-3.5 h-3.5 mr-1.5 text-purple-400" />
                        Forecasting
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => setActiveTab("mitre")}
                        className="h-8 justify-start text-xs border-slate-700 bg-slate-800/80 text-slate-200 hover:bg-slate-700 hover:text-white"
                      >
                        <Layers className="w-3.5 h-3.5 mr-1.5 text-indigo-400" />
                        MITRE Matrix
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => setActiveTab("packets")}
                        className="h-8 justify-start text-xs border-slate-700 bg-slate-800/80 text-slate-200 hover:bg-slate-700 hover:text-white"
                      >
                        <Activity className="w-3.5 h-3.5 mr-1.5 text-emerald-400" />
                        Packets & DPI
                      </Button>
                    </div>
                  </CardContent>
                </Card>

                {/* Compact ML Performance Summary Card */}
                <Card className="border-border bg-white dark:bg-slate-900 shadow-md flex flex-col justify-between">
                  <CardHeader className="pb-2">
                    <div className="flex items-center justify-between">
                      <Badge className="bg-emerald-600 text-white text-[10px]">Evaluated ML World Model</Badge>
                      <span className="text-[10px] font-mono text-slate-500">CSE-CIC-IDS2018</span>
                    </div>
                    <CardTitle className="text-base font-bold flex items-center gap-2 mt-2">
                      <BrainCircuit className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                      Model Performance Summary
                    </CardTitle>
                    <CardDescription className="text-xs">
                      LSTM Neural Network benchmarked against linear baseline comparator.
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="pt-2 space-y-3">
                    <div className="grid grid-cols-3 gap-2 text-center text-xs font-mono">
                      <div className="p-2 rounded bg-slate-50 dark:bg-slate-800/60 border border-slate-100 dark:border-slate-800">
                        <p className="text-[10px] uppercase font-sans text-slate-400">F1 Score</p>
                        <p className="font-extrabold text-emerald-600 text-sm">94.8%</p>
                      </div>
                      <div className="p-2 rounded bg-slate-50 dark:bg-slate-800/60 border border-slate-100 dark:border-slate-800">
                        <p className="text-[10px] uppercase font-sans text-slate-400">Precision</p>
                        <p className="font-extrabold text-emerald-600 text-sm">92.6%</p>
                      </div>
                      <div className="p-2 rounded bg-slate-50 dark:bg-slate-800/60 border border-slate-100 dark:border-slate-800">
                        <p className="text-[10px] uppercase font-sans text-slate-400">Recall</p>
                        <p className="font-extrabold text-emerald-600 text-sm">97.1%</p>
                      </div>
                    </div>
                    <Button
                      size="sm"
                      onClick={() => setActiveTab("ml")}
                      className="w-full h-8 text-xs bg-indigo-600 hover:bg-indigo-700 text-white font-semibold flex items-center justify-center gap-1.5"
                    >
                      View Full Benchmarks & Scores
                      <ArrowRight className="w-3.5 h-3.5" />
                    </Button>
                  </CardContent>
                </Card>

                {/* MITRE Threat Horizon Quick Summary */}
                <Card className="border-border bg-white dark:bg-slate-900 shadow-md flex flex-col justify-between">
                  <CardHeader className="pb-2">
                    <div className="flex items-center justify-between">
                      <Badge variant="outline" className="text-[10px] border-purple-400 text-purple-600 dark:text-purple-400">
                        Kill-Chain Mapping
                      </Badge>
                      <span className="text-[10px] font-mono text-slate-500">14 MITRE Tactics</span>
                    </div>
                    <CardTitle className="text-base font-bold flex items-center gap-2 mt-2">
                      <Layers className="w-4 h-4 text-purple-600 dark:text-purple-400" />
                      Attack Stage Alignment
                    </CardTitle>
                    <CardDescription className="text-xs">
                      Correlates real-time packet telemetry to enterprise tactics & techniques.
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="pt-2 space-y-3">
                    <div className="flex items-center justify-between text-xs p-2 rounded bg-purple-50/50 dark:bg-purple-950/20 border border-purple-100 dark:border-purple-900/40">
                      <span className="text-slate-600 dark:text-slate-400">Current Threat State:</span>
                      <Badge className="bg-emerald-600 text-white text-[10px]">Normal Baseline</Badge>
                    </div>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => setActiveTab("mitre")}
                      className="w-full h-8 text-xs border-purple-200 dark:border-purple-900 text-purple-700 dark:text-purple-300 hover:bg-purple-50 dark:hover:bg-purple-950/40 font-semibold flex items-center justify-center gap-1.5"
                    >
                      Open MITRE ATT&CK Matrix
                      <ArrowRight className="w-3.5 h-3.5" />
                    </Button>
                  </CardContent>
                </Card>
              </div>

              {/* Row 3: Active Threat Operations & Incident Detection */}
              <div className="grid gap-4 grid-cols-1 lg:grid-cols-2">
                <ThreatDetectionPanel excludeLow />
                <AlertNotifications />
              </div>

              {/* Row 4: Connected Endpoints & Security Block Rules */}
              <div className="grid gap-4 grid-cols-1 lg:grid-cols-2">
                <ObservedDevicesCard />
                <BlockedSitesCard />
              </div>
            </>
          )}

          {/* ========================================================= */}
          {/* 2. DEDICATED SIDEBAR SECTIONS                             */}
          {/* ========================================================= */}
          {activeTab === "topology" && (
            <NetworkTopologyPanel onNavigateToTraffic={() => setActiveTab("packets")} />
          )}

          {activeTab === "workbench" && (
            <WorkbenchPage />
          )}

          {activeTab === "forecasting" && (
            <AttackForecastingPanel />
          )}

          {activeTab === "ml" && (
            <MLBenchmarkPanel />
          )}

          {activeTab === "mitre" && (
            <MitreAttackMatrix />
          )}

          {activeTab === "scanner" && (
            <div className="space-y-6">
              <WebsiteThreatScanner />
              <div className="grid gap-4 lg:grid-cols-2">
                <ThreatDetectionPanel />
                <BlockedSitesCard />
              </div>
            </div>
          )}

          {activeTab === "packets" && (
            <div className="space-y-6">
              <TrafficChartPanel />
              <PacketInspectionPanel />
            </div>
          )}

          {activeTab === "inspection" && (
            <PacketInspectionPanel />
          )}

          {/* ========================================================= */}
          {/* 3. THREAT DETECTION (BALANCED HIERARCHICAL LAYOUT)        */}
          {/* ========================================================= */}
          {activeTab === "threats" && (
            <div className="space-y-6">
              {/* Top Row: Active Threat Watch & Live Alert Notifications */}
              <div className="grid gap-4 grid-cols-1 lg:grid-cols-2">
                <ThreatDetectionPanel />
                <AlertNotifications />
              </div>

              {/* Middle Row: Containment & Monitored Device Endpoints */}
              <div className="grid gap-4 grid-cols-1 lg:grid-cols-2">
                <BlockedSitesCard />
                <ObservedDevicesCard />
              </div>

              {/* Bottom Row: Deep Packet Telemetry & Inspection */}
              <PacketInspectionPanel />
            </div>
          )}

          {activeTab === "traffic" && (
            <div className="space-y-6">
              <TrafficChartPanel />
              <TrafficAnalysisPanel />
            </div>
          )}

          {activeTab === "actions" && (
            <ActionLogs />
          )}

          {activeTab === "archive" && (
            <NotificationArchive />
          )}

          {activeTab === "settings" && (
            <div className="space-y-6">
              <SettingsPanel />
              <AdminPanel />
            </div>
          )}
        </main>
      </div>
    </div>
  )
}
