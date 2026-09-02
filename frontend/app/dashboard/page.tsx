"use client"

import { useState, useEffect } from "react"
import { healthCheck, type HealthCheckResponse } from "../../lib/api"
import { DashboardSidebar } from "@/components/dashboard/dashboard-sidebar"
import { DashboardHeader } from "@/components/dashboard/dashboard-header"
import { StatCards } from "@/components/dashboard/stat-cards"
import { TrafficChartPanel, PacketInspectionPanel, TrafficAnalysisPanel } from "@/components/dashboard/traffic"
import { BlockedSitesCard, ObservedDevicesCard, ThreatDetectionPanel, ThreatResponsePanel, OSProtection } from "@/components/dashboard/threats"
import { SettingsPanel, AdminPanel, ActionLogs } from "@/components/dashboard/admin"
import { AlertNotifications, NotificationArchive } from "@/components/dashboard/alerts"
import { MitreAttackMatrix } from "@/components/dashboard/mitre-matrix"
import { WebsiteThreatScanner } from "@/components/dashboard/website-scanner"
import { MLBenchmarkPanel } from "@/components/dashboard/ml-benchmark"
import { AttackForecastingPanel } from "@/components/dashboard/forecasting"
import { NetworkTopologyPanel } from "@/components/dashboard/network-topology"
import WorkbenchPage from "@/app/workbench/page"

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
    <div className="flex min-h-screen overflow-hidden bg-background">
      <DashboardSidebar
        activeTab={activeTab}
        onTabChange={setActiveTab}
        mobileOpen={mobileNavOpen}
        onMobileOpenChange={setMobileNavOpen}
      />
      <div className="flex flex-1 flex-col overflow-hidden">
        <DashboardHeader
          activeTab={activeTab}
          onTabChange={setActiveTab}
          onMenuClick={() => setMobileNavOpen(true)}
        />
        <main className="flex-1 space-y-6 overflow-y-auto p-4 sm:p-6">
          {activeTab === "overview" && (
            <>
              {/* Core Security Status & Health Header */}
              <StatCards healthData={healthData} />
              
              {/* Primary Attack Forecasting & 5-Step Infiltration Trajectory */}
              <AttackForecastingPanel />

              {/* MITRE ATT&CK 14-Stage Kill Chain Matrix */}
              <MitreAttackMatrix />

              {/* Live Traffic & Threat Response Section */}
              <div className="grid gap-6 xl:grid-cols-3">
                <div className="space-y-6 xl:col-span-2">
                  <TrafficChartPanel />
                  <div className="grid gap-6 lg:grid-cols-2">
                    <ThreatResponsePanel />
                    <AlertNotifications />
                  </div>
                </div>
                <div className="space-y-6">
                  <ThreatDetectionPanel excludeLow />
                  <WebsiteThreatScanner />
                </div>
              </div>

              {/* Device Connectivity / Network Topology Mapping */}
              <NetworkTopologyPanel onNavigateToTraffic={() => setActiveTab("packets")} />

              {/* ML Model Benchmark Baseline Comparison */}
              <MLBenchmarkPanel />
            </>
          )}

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
            <>
              <MitreAttackMatrix />
              <WebsiteThreatScanner />
            </>
          )}

          {activeTab === "scanner" && (
            <>
              <WebsiteThreatScanner />
              <div className="grid gap-4 lg:grid-cols-2">
                <ThreatDetectionPanel />
                <BlockedSitesCard />
              </div>
            </>
          )}

          {activeTab === "packets" && (
            <>
              <TrafficChartPanel />
              <PacketInspectionPanel />
            </>
          )}

          {activeTab === "inspection" && (
            <PacketInspectionPanel />
          )}

          {activeTab === "threats" && (
            <>
              <WebsiteThreatScanner />
              <div className="grid gap-4 lg:grid-cols-3">
                <div className="lg:col-span-2">
                  <PacketInspectionPanel />
                </div>
                <ThreatDetectionPanel />
              </div>
              <MitreAttackMatrix />
              <div className="grid gap-4 lg:grid-cols-2">
                <ThreatResponsePanel />
                <AlertNotifications />
              </div>
              <BlockedSitesCard />
              <OSProtection />
            </>
          )}

          {activeTab === "traffic" && (
            <>
              <TrafficChartPanel />
              <TrafficAnalysisPanel />
            </>
          )}

          {activeTab === "actions" && (
            <ActionLogs />
          )}

          {activeTab === "archive" && (
            <NotificationArchive />
          )}

          {activeTab === "settings" && (
            <>
              <SettingsPanel />
              <AdminPanel />
            </>
          )}
        </main>
      </div>
    </div>
  )
}
