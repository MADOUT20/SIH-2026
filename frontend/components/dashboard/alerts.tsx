"use client"
// Alert and notification panels used in the monitoring dashboard.

// ===== Consolidated Alerts & Notifications =====

import { useEffect, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { ScrollArea } from "@/components/ui/scroll-area"
import { AlertCircle, Archive, ChevronLeft, ChevronRight, RefreshCw } from "lucide-react"
import { getNotifications, type Notification } from "@/lib/api"

const DASHBOARD_REFRESH_EVENT = "netguard:dashboard-refresh"

function getSeverityBadgeStyle(severity: string) {
  if (severity === "CRITICAL") {
    return "border-rose-300 bg-rose-100 text-rose-800 dark:border-rose-900/60 dark:bg-rose-950/60 dark:text-rose-300"
  }
  if (severity === "HIGH") {
    return "border-orange-300 bg-orange-100 text-orange-800 dark:border-orange-900/60 dark:bg-orange-950/60 dark:text-orange-300"
  }
  if (severity === "MEDIUM") {
    return "border-amber-300 bg-amber-100 text-amber-800 dark:border-amber-900/60 dark:bg-amber-950/60 dark:text-amber-300"
  }
  return "border-slate-200 bg-slate-100 text-slate-700 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300"
}

function formatTitle(notification: Notification) {
  return notification.title || notification.type.replace(/_/g, " ")
}

function useNotificationFeed() {
  const [notifications, setNotifications] = useState<Notification[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")

  const fetchNotifications = async () => {
    try {
      const data = await getNotifications()
      setNotifications(data.notifications || [])
      setError("")
    } catch (err) {
      console.error("Failed to fetch notifications:", err)
      setError("Failed to load notifications")
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    let isMounted = true
    const load = async () => {
      try {
        const data = await getNotifications()
        if (isMounted) {
          setNotifications(data.notifications || [])
          setError("")
          setLoading(false)
        }
      } catch (err) {
        if (isMounted) {
          console.error("Failed to fetch notifications:", err)
          setError("Failed to load notifications")
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
  }, [])

  return { notifications, loading, error, fetchNotifications }
}

// Alert Notifications Component
export function AlertNotifications() {
  const { notifications, loading, error, fetchNotifications } = useNotificationFeed()
  const alerts = notifications.slice(0, 4)
  const [activeIndex, setActiveIndex] = useState(0)

  const safeActiveIndex = alerts.length > 0 ? Math.min(activeIndex, alerts.length - 1) : 0
  const activeAlert = alerts[safeActiveIndex]

  return (
    <Card className="border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900">
      <CardHeader className="flex flex-row items-center justify-between pb-3">
        <CardTitle className="flex items-center gap-2 text-slate-900 dark:text-slate-100">
          <AlertCircle className="w-5 h-5 text-rose-500 dark:text-rose-400" />
          Active Alerts
        </CardTitle>
        <Button size="sm" variant="ghost" onClick={fetchNotifications} className="h-8 w-8 p-0 text-slate-600 dark:text-slate-400">
          <RefreshCw className="w-4 h-4" />
        </Button>
      </CardHeader>
      <CardContent className="space-y-3">
        {error && <p className="text-sm text-red-500">{error}</p>}
        {loading && alerts.length === 0 ? (
          <p className="text-sm text-slate-500 dark:text-slate-400">Loading alerts...</p>
        ) : alerts.length === 0 ? (
          <p className="text-sm text-slate-500 dark:text-slate-400">No active alerts right now.</p>
        ) : (
          <>
            <div className="flex items-center justify-between gap-3">
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Alert {safeActiveIndex + 1} of {alerts.length}
              </p>
              {alerts.length > 1 && (
                <div className="flex items-center gap-1">
                  <Button
                    size="icon"
                    variant="outline"
                    className="h-8 w-8 border-slate-200 text-slate-700 hover:bg-slate-100 dark:border-slate-800 dark:text-slate-300 dark:hover:bg-slate-800"
                    onClick={() => setActiveIndex((currentIndex) => Math.max(0, currentIndex - 1))}
                    disabled={safeActiveIndex === 0}
                  >
                    <ChevronLeft className="h-4 w-4" />
                    <span className="sr-only">Previous alert</span>
                  </Button>
                  <Button
                    size="icon"
                    variant="outline"
                    className="h-8 w-8 border-slate-200 text-slate-700 hover:bg-slate-100 dark:border-slate-800 dark:text-slate-300 dark:hover:bg-slate-800"
                    onClick={() => setActiveIndex((currentIndex) => Math.min(alerts.length - 1, currentIndex + 1))}
                    disabled={safeActiveIndex === alerts.length - 1}
                  >
                    <ChevronRight className="h-4 w-4" />
                    <span className="sr-only">Next alert</span>
                  </Button>
                </div>
              )}
            </div>
            <div className="flex min-h-36 items-start justify-between gap-3 rounded-xl border border-slate-200 bg-slate-50 p-4 transition-colors dark:border-slate-800 dark:bg-slate-800/50">
              <div className="flex-1 space-y-2">
                <p className="font-semibold text-sm text-slate-900 dark:text-slate-100">{formatTitle(activeAlert)}</p>
                <p className="text-xs leading-5 text-slate-600 dark:text-slate-300">{activeAlert.message}</p>
                <p className="text-xs text-slate-400 dark:text-slate-400 font-mono">{new Date(activeAlert.timestamp).toLocaleString()}</p>
              </div>
              <Badge variant="outline" className={`text-xs font-semibold shrink-0 ${getSeverityBadgeStyle(activeAlert.severity)}`}>
                {activeAlert.severity}
              </Badge>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  )
}

// Notification Archive Component
export function NotificationArchive() {
  const { notifications, loading, error, fetchNotifications } = useNotificationFeed()

  return (
    <Card className="border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900">
      <CardHeader className="flex flex-row items-center justify-between pb-3">
        <CardTitle className="flex items-center gap-2 text-slate-900 dark:text-slate-100">
          <Archive className="w-5 h-5 text-indigo-500 dark:text-indigo-400" />
          Notification Activity
        </CardTitle>
        <Button size="sm" variant="ghost" onClick={fetchNotifications} className="h-8 w-8 p-0 text-slate-600 dark:text-slate-400">
          <RefreshCw className="w-4 h-4" />
        </Button>
      </CardHeader>
      <CardContent className="space-y-3">
        {error && <p className="text-sm text-red-500">{error}</p>}
        {loading && notifications.length === 0 ? (
          <p className="text-sm text-slate-500 dark:text-slate-400">Loading notifications...</p>
        ) : notifications.length === 0 ? (
          <p className="text-slate-500 dark:text-slate-400 text-xs">No notification history yet.</p>
        ) : (
          <ScrollArea className="h-96 pr-3">
            <div className="space-y-2">
              {notifications.map((alert) => (
                <div
                  key={alert.id}
                  className="space-y-1 rounded-xl border border-slate-200 bg-slate-50/70 p-3 text-xs transition-colors dark:border-slate-800 dark:bg-slate-800/40"
                >
                  <div className="flex items-center justify-between gap-3">
                    <p className="font-semibold text-slate-900 dark:text-slate-100">{formatTitle(alert)}</p>
                    <Badge variant="outline" className={`text-[10px] font-semibold ${getSeverityBadgeStyle(alert.severity)}`}>
                      {alert.severity}
                    </Badge>
                  </div>
                  <p className="text-slate-600 dark:text-slate-300 text-xs">{alert.message}</p>
                  <p className="text-[10px] text-slate-400 dark:text-slate-400 font-mono">{new Date(alert.timestamp).toLocaleString()}</p>
                </div>
              ))}
            </div>
          </ScrollArea>
        )}
      </CardContent>
    </Card>
  )
}
