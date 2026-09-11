"use client"
// Top header for the dashboard, including status and quick actions.

import { useEffect, useMemo, useRef, useState } from "react"
import { Bell, Menu, User, Wifi, Laptop, Unlink, RefreshCw } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { ThemeToggle } from "@/components/theme-toggle"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { UserProfileModal } from "@/components/user-profile-modal"
import { ConnectDeviceModal } from "@/components/dashboard/connect-device-modal"
import { useDevice } from "@/context/device-context"
import Link from "next/link"
import { getNotifications, getUsers, type Notification, type User as AppUser } from "@/lib/api"
import { deduplicateBy, createEntityKey } from "@/lib/dedup"

const DASHBOARD_REFRESH_EVENT = "netguard:dashboard-refresh"

const tabLabels: Record<string, string> = {
  overview: "SOC Dashboard Overview",
  topology: "Network Topology & Device Connectivity",
  forecasting: "LSTM Attack Forecasting & World Model",
  workbench: "Offline Workbench (PCAP/CSV Analysis)",
  mitre: "MITRE ATT&CK Matrix & Kill-Chain",
  packets: "Traffic & Packet Inspection",
  ml: "Benchmarks & Scores — ML Evaluation",
  scanner: "Website Threat Scanner",
  threats: "Threat Detection & Response",
  inspection: "Deep Packet Inspection",
  traffic: "Traffic Analysis",
  actions: "Action Taken History",
  archive: "Notification Archive",
  settings: "System Settings",
}

interface DashboardHeaderProps {
  activeTab: string
  onTabChange?: (tab: string) => void
  onMenuClick?: () => void
}

export function DashboardHeader({ activeTab, onTabChange, onMenuClick }: DashboardHeaderProps) {
  const { connectedDevice, openConnectModal, disconnectDevice, appMode } = useDevice()
  const [profileOpen, setProfileOpen] = useState(false)
  const [user, setUser] = useState<AppUser | null>(null)
  const [archivedAlerts, setArchivedAlerts] = useState<Notification[]>([])
  const [showArchived, setShowArchived] = useState(false)
  const [alerts, setAlerts] = useState<Notification[]>([])
  const [loadingAlerts, setLoadingAlerts] = useState(true)
  const dismissedAlertIdsRef = useRef<Set<string>>(new Set())

  const archiveAlerts = (items: Notification[]) => {
    setArchivedAlerts((currentAlerts) => {
      const nextAlerts = [...items, ...currentAlerts]
      return deduplicateBy(nextAlerts, (a) => a.id, "DashboardHeader.archivedAlerts")
    })
  }

  useEffect(() => {
    let isMounted = true
    const fetchAlerts = async () => {
      try {
        const data = await getNotifications()
        if (isMounted) {
          const incomingAlerts = data.notifications || []
          const dedupedIncoming = deduplicateBy(
            incomingAlerts.filter((alert) => !dismissedAlertIdsRef.current.has(alert.id)),
            (a, i) => a.id || `${a.type}-${a.timestamp}-${i}`,
            "DashboardHeader.alerts"
          )
          setAlerts(dedupedIncoming)
          setLoadingAlerts(false)
        }
      } catch (err) {
        if (isMounted) {
          console.warn("Notifications currently unavailable:", err instanceof Error ? err.message : String(err))
          setLoadingAlerts(false)
        }
      }
    }

    const fetchUser = async () => {
      try {
        const data = await getUsers()
        if (isMounted && data.users && data.users.length > 0) {
          setUser(data.users[0])
        }
      } catch (err) {
        if (isMounted) console.warn("User profile currently unavailable:", err instanceof Error ? err.message : String(err))
      }
    }

    fetchAlerts()
    fetchUser()
    const interval = setInterval(fetchAlerts, 3000)
    const handleRefresh = () => fetchAlerts()
    window.addEventListener(DASHBOARD_REFRESH_EVENT, handleRefresh)

    return () => {
      isMounted = false
      clearInterval(interval)
      window.removeEventListener(DASHBOARD_REFRESH_EVENT, handleRefresh)
    }
  }, [])

  const activeAlertCount = alerts.length
  const archivedAlertCount = archivedAlerts.length

  const clearAllAlerts = () => {
    if (alerts.length === 0) {
      return
    }

    alerts.forEach((alert) => dismissedAlertIdsRef.current.add(alert.id))
    archiveAlerts(alerts)
    setAlerts([])
  }

  const toggleMode = (newMode: "live" | "demo") => {
    if (typeof window !== "undefined") {
      localStorage.setItem("netguard_app_mode", newMode)
      window.dispatchEvent(new CustomEvent("netguard:mode-change", { detail: { mode: newMode } }))
      window.dispatchEvent(new Event(DASHBOARD_REFRESH_EVENT))
    }
  }

  return (
    <header className="flex min-h-16 shrink-0 items-center justify-between gap-3 border-b border-border bg-card px-4 py-3 sm:px-6">
      <div className="flex min-w-0 items-center gap-3 sm:gap-4">
        <Button
          variant="ghost"
          size="icon"
          className="shrink-0 md:hidden"
          onClick={onMenuClick}
        >
          <Menu className="h-5 w-5" />
          <span className="sr-only">Open navigation</span>
        </Button>
        <h1 className="truncate text-base font-semibold text-foreground sm:text-lg">
          {tabLabels[activeTab] || "Dashboard"}
        </h1>
        <Badge variant="outline" className="hidden sm:inline-flex text-xs border-emerald-500/30 text-emerald-500">
          System Online
        </Badge>
      </div>
      <div className="flex shrink-0 items-center gap-2 sm:gap-3">
        {/* Connected Device Scope Indicator */}
        <div className="hidden md:flex items-center gap-2 rounded-full border border-border bg-muted/60 px-3 py-1 text-xs shadow-inner">
          {connectedDevice ? (
            <div className="flex items-center gap-2">
              <div className="flex items-center gap-1.5 font-medium">
                <span className="relative flex h-2 w-2">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75"></span>
                  <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500"></span>
                </span>
                <span className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">
                  CONNECTED:
                </span>
                <span className="font-bold text-foreground max-w-[130px] truncate" title={connectedDevice.name}>
                  {connectedDevice.name}
                </span>
                <span className="font-mono text-[10px] text-muted-foreground">({connectedDevice.ip})</span>
              </div>
              <Badge className="h-4 bg-emerald-600 hover:bg-emerald-600 text-[9px] font-bold text-white px-1.5">
                ● ACTIVE
              </Badge>
              <div className="flex items-center gap-1 pl-1">
                <Button
                  size="sm"
                  variant="ghost"
                  className="h-5 text-[10px] px-1.5 text-indigo-600 hover:text-indigo-700 hover:bg-indigo-50 dark:text-indigo-400 dark:hover:bg-indigo-950/40 font-semibold"
                  onClick={openConnectModal}
                >
                  Change
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  className="h-5 text-[10px] px-1.5 text-rose-500 hover:text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950/40"
                  onClick={disconnectDevice}
                  title="Disconnect device"
                >
                  Disconnect
                </Button>
              </div>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <div className="flex items-center gap-1.5 text-muted-foreground">
                <Wifi className="h-3.5 w-3.5 text-slate-400" />
                <span className="text-[10px] font-semibold uppercase tracking-wider">CONNECTED:</span>
                <span className="italic text-[11px] text-slate-400">None</span>
              </div>
              <Button
                size="sm"
                className="h-5 text-[10px] px-2 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold gap-1 shadow-sm"
                onClick={openConnectModal}
              >
                <Wifi className="h-3 w-3" />
                Connect Device
              </Button>
            </div>
          )}
        </div>

        {/* Global Mode Switcher */}
        <div className="flex items-center gap-1 rounded-full border border-border bg-muted/60 p-1 text-xs shadow-inner">
          <Button
            size="sm"
            variant={appMode === "live" ? "default" : "ghost"}
            className={appMode === "live" ? "h-6 rounded-full bg-emerald-600 hover:bg-emerald-700 text-white font-bold text-[11px] px-2.5 shadow-sm" : "h-6 rounded-full text-muted-foreground text-[11px] px-2.5"}
            onClick={() => toggleMode("live")}
          >
            🟢 LIVE MODE
          </Button>
          <Button
            size="sm"
            variant={appMode === "demo" ? "default" : "ghost"}
            className={appMode === "demo" ? "h-6 rounded-full bg-amber-600 hover:bg-amber-700 text-white font-bold text-[11px] px-2.5 shadow-sm" : "h-6 rounded-full text-muted-foreground text-[11px] px-2.5"}
            onClick={() => toggleMode("demo")}
          >
            🟣 DEMO MODE
          </Button>
        </div>

        <ThemeToggle />
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="relative">
              <Bell className="h-5 w-5" />
              {!loadingAlerts && activeAlertCount > 0 && (
                <span className="absolute -top-0.5 -right-0.5 flex h-4 w-4 items-center justify-center rounded-full bg-destructive text-[10px] text-destructive-foreground font-semibold">
                  {activeAlertCount}
                </span>
              )}
              <span className="sr-only">Notifications</span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-96">
            <div className="flex items-center gap-2 px-3 py-2 border-b border-border">
              <Button
                variant={showArchived ? "ghost" : "default"}
                size="sm"
                className="h-6 text-xs"
                onClick={() => setShowArchived(false)}
              >
                Active ({activeAlertCount})
              </Button>
              <Button
                variant={showArchived ? "default" : "ghost"}
                size="sm"
                className="h-6 text-xs"
                onClick={() => setShowArchived(true)}
              >
                Archive ({archivedAlertCount})
              </Button>
            </div>
            {!showArchived && activeAlertCount > 0 && (
              <Button
                variant="ghost"
                size="sm"
                className="w-full h-6 px-2 text-xs text-muted-foreground hover:text-foreground justify-center"
                onClick={clearAllAlerts}
              >
                Clear All
              </Button>
            )}
            <DropdownMenuSeparator />
            {loadingAlerts ? (
              <div className="p-4 text-center text-sm text-slate-500">Loading notifications...</div>
            ) : (showArchived ? archivedAlertCount > 0 : activeAlertCount > 0) ? (
              <div className="max-h-96 overflow-y-auto space-y-2 p-2">
                {(showArchived ? archivedAlerts : alerts).map((alert) => {
                  const severity = alert.severity || "MEDIUM"
                  const alertColor = severity === "CRITICAL"
                    ? "border-destructive/30 bg-destructive/5"
                    : severity === "HIGH"
                      ? "border-red-500/30 bg-red-500/5"
                      : severity === "MEDIUM"
                        ? "border-yellow-500/30 bg-yellow-500/5"
                        : "border-blue-500/30 bg-blue-500/5"

                  return (
                    <div key={createEntityKey("header-alert", alert.id, [alert.type, alert.timestamp])} className={`p-3 rounded-lg border ${alertColor} space-y-2`}>
                      <div className="flex items-center justify-between">
                        <Badge
                          variant="outline"
                          className={
                            severity === "CRITICAL"
                              ? "bg-destructive text-destructive-foreground border-destructive"
                              : severity === "HIGH"
                                ? "bg-red-600 text-red-50 border-red-600"
                                : severity === "MEDIUM"
                                  ? "bg-yellow-600 text-yellow-50 border-yellow-600"
                                  : "bg-blue-600 text-blue-50 border-blue-600"
                          }
                        >
                          {severity}
                        </Badge>
                        <span className="text-xs text-muted-foreground">
                          {new Date(alert.timestamp).toLocaleString()}
                        </span>
                      </div>
                      <div className="space-y-1 text-sm">
                        <p className="font-medium text-foreground">{alert.title}</p>
                        <p className="text-xs text-muted-foreground">{alert.message}</p>
                      </div>
                    </div>
                  )
                })}
              </div>
            ) : (
              <div className="p-4 text-center text-sm text-slate-500">
                {showArchived ? "No archived notifications" : "All clear! No active threats."}
              </div>
            )}
          </DropdownMenuContent>
        </DropdownMenu>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon">
              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary/10">
                <User className="h-4 w-4 text-primary" />
              </div>
              <span className="sr-only">User menu</span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <div className="px-3 py-2">
              <p className="text-sm font-medium text-foreground">{user ? user.email : "Loading..."}</p>
              <p className="text-xs text-muted-foreground">{user ? user.role : ""}</p>
            </div>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={() => setProfileOpen(true)}>
              Profile
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => onTabChange?.("settings")}>
              Settings
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      {/* User Profile Modal */}
      <UserProfileModal 
        open={profileOpen} 
        onOpenChange={setProfileOpen}
        user={user}
      />

      {/* Global Connect Device Modal */}
      <ConnectDeviceModal />
    </header>
  )
}
