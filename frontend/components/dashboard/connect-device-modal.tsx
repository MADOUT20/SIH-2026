"use client"

import { useState } from "react"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { useDevice } from "@/context/device-context"
import {
  Laptop,
  Smartphone,
  Server,
  Router as RouterIcon,
  HardDrive,
  RefreshCw,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Wifi,
  WifiOff,
  Activity,
  ArrowRight,
  Lock,
} from "lucide-react"
import { createEntityKey, deduplicateBy } from "@/lib/dedup"
import type { DiscoveredDevice } from "@/lib/api"

export function ConnectDeviceModal() {
  const {
    isConnectModalOpen,
    setIsConnectModalOpen,
    discoveredDevices,
    isDiscovering,
    discoveryError,
    refreshDiscovery,
    connectDevice,
    connectedDevice,
    appMode,
  } = useDevice()

  const [selectedDevice, setSelectedDevice] = useState<DiscoveredDevice | null>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [connectError, setConnectError] = useState<string | null>(null)
  const [step, setStep] = useState<"discover" | "consent">("discover")

  const handleOpenChange = (open: boolean) => {
    setIsConnectModalOpen(open)
    if (!open) {
      setSelectedDevice(null)
      setStep("discover")
      setConnectError(null)
    }
  }

  const handleSelectDevice = (device: DiscoveredDevice) => {
    setSelectedDevice(device)
    setConnectError(null)
    setStep("consent")
  }

  const handleConfirmConnect = async () => {
    if (!selectedDevice || isSubmitting) return
    setIsSubmitting(true)
    setConnectError(null)
    try {
      await connectDevice(selectedDevice, true)
      setIsConnectModalOpen(false)
      setSelectedDevice(null)
      setStep("discover")
    } catch (err: any) {
      setConnectError(err?.message || "Failed to connect to device.")
    } finally {
      setIsSubmitting(false)
    }
  }

  const getDeviceIcon = (type?: string, isGw?: boolean) => {
    if (isGw) return RouterIcon
    const t = (type || "").toLowerCase()
    if (t.includes("mobile") || t.includes("phone") || t.includes("android") || t.includes("ios")) return Smartphone
    if (t.includes("server") || t.includes("database")) return Server
    if (t.includes("iot") || t.includes("sensor")) return HardDrive
    return Laptop
  }

  return (
    <Dialog open={isConnectModalOpen} onOpenChange={handleOpenChange}>
      <DialogContent className="max-w-lg border-slate-200 bg-white text-slate-900 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-100 shadow-2xl">
        {step === "discover" ? (
          <>
            <DialogHeader className="space-y-1 pb-2">
              <div className="flex items-center justify-between">
                <DialogTitle className="flex items-center gap-2 text-base font-bold text-slate-900 dark:text-slate-100">
                  <Wifi className="h-5 w-5 text-indigo-600 dark:text-indigo-400" />
                  Connect a Device
                </DialogTitle>
                <Badge
                  variant="outline"
                  className={
                    appMode === "demo"
                      ? "bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/30 text-[10px]"
                      : "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30 text-[10px]"
                  }
                >
                  {appMode === "demo" ? "DEMO / SEEDED DATA" : "LOCAL NETWORK DISCOVERY"}
                </Badge>
              </div>
              <DialogDescription className="text-xs text-slate-500 dark:text-slate-400">
                Discovering devices on your local network. Select a device to monitor with permission.
              </DialogDescription>
            </DialogHeader>

            {discoveryError && (
              <div className="rounded-lg border border-amber-300 bg-amber-50 p-3 text-xs text-amber-800 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-300 flex items-start gap-2">
                <AlertTriangle className="h-4 w-4 shrink-0 text-amber-600 mt-0.5" />
                <div>
                  <p className="font-semibold">Discovery Notice</p>
                  <p className="mt-0.5">{discoveryError}</p>
                </div>
              </div>
            )}

            <div className="max-h-[340px] overflow-y-auto space-y-2 pr-1 pt-1">
              {isDiscovering && discoveredDevices.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-10 text-center space-y-3">
                  <RefreshCw className="h-8 w-8 animate-spin text-indigo-500" />
                  <div className="space-y-1">
                    <p className="text-sm font-medium text-slate-700 dark:text-slate-300">
                      Scanning local subnet & ARP table...
                    </p>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      Identifying available network endpoints and interfaces
                    </p>
                  </div>
                </div>
              ) : discoveredDevices.length === 0 ? (
                <div className="rounded-xl border border-dashed border-slate-300 p-8 text-center dark:border-slate-800 space-y-2">
                  <WifiOff className="h-8 w-8 text-slate-400 mx-auto" />
                  <p className="text-sm font-semibold text-slate-700 dark:text-slate-300">
                    No nearby devices currently detected
                  </p>
                  <p className="text-xs text-slate-500 dark:text-slate-400 max-w-xs mx-auto leading-relaxed">
                    Make sure the device is connected to the same local network and that monitoring permissions are available.
                  </p>
                </div>
              ) : (
                deduplicateBy(
                  discoveredDevices,
                  (d) => d.id || d.ip,
                  "ConnectDeviceModal.devices"
                ).map((dev) => {
                  const Icon = getDeviceIcon(dev.device_type, dev.is_gateway)
                  const isCurrent = connectedDevice?.ip === dev.ip || connectedDevice?.id === dev.id
                  const hasTraffic = dev.has_traffic || (dev.packet_count || 0) > 0

                  return (
                    <div
                      key={createEntityKey("modal-dev", dev.id, [dev.ip])}
                      onClick={() => handleSelectDevice(dev)}
                      className={`group relative flex items-center justify-between rounded-xl border p-3.5 transition-all cursor-pointer ${
                        isCurrent
                          ? "border-indigo-500/60 bg-indigo-500/5 dark:bg-indigo-500/10 shadow-sm"
                          : "border-slate-200/80 bg-slate-50/50 hover:border-indigo-400/50 hover:bg-indigo-50/40 dark:border-slate-800 dark:bg-slate-800/40 dark:hover:border-indigo-500/40 dark:hover:bg-slate-800/80"
                      }`}
                    >
                      <div className="flex items-center gap-3 min-w-0">
                        <div
                          className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ${
                            isCurrent
                              ? "bg-indigo-600 text-white"
                              : dev.is_local_host
                              ? "bg-emerald-600/10 text-emerald-600 dark:text-emerald-400"
                              : "bg-slate-200 text-slate-700 dark:bg-slate-800 dark:text-slate-300 group-hover:bg-indigo-600 group-hover:text-white"
                          }`}
                        >
                          <Icon className="h-5 w-5" />
                        </div>
                        <div className="min-w-0 space-y-0.5">
                          <div className="flex items-center gap-2">
                            <span className="truncate text-sm font-semibold text-slate-900 dark:text-slate-100">
                              {dev.name}
                            </span>
                            {isCurrent && (
                              <Badge className="h-4 px-1.5 text-[9px] bg-indigo-600 text-white font-bold">
                                ACTIVE
                              </Badge>
                            )}
                            {dev.is_local_host && !isCurrent && (
                              <Badge variant="outline" className="h-4 px-1.5 text-[9px] text-emerald-600 border-emerald-500/40">
                                THIS HOST
                              </Badge>
                            )}
                          </div>
                          <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400 font-mono">
                            <span>{dev.ip}</span>
                            {dev.mac && (
                              <>
                                <span>•</span>
                                <span className="text-[11px] text-slate-400 dark:text-slate-500">{dev.mac}</span>
                              </>
                            )}
                          </div>
                          <div className="flex items-center gap-2 pt-0.5">
                            <span className="inline-flex items-center gap-1 text-[11px] font-medium text-slate-600 dark:text-slate-400">
                              <span
                                className={`h-1.5 w-1.5 rounded-full ${
                                  hasTraffic ? "bg-emerald-500 animate-pulse" : "bg-emerald-400"
                                }`}
                              />
                              {dev.device_type || "Endpoint"} • Available
                            </span>
                            {hasTraffic && (
                              <span className="text-[10px] text-emerald-600 dark:text-emerald-400 font-medium">
                                ({dev.packet_count} pkts observed)
                              </span>
                            )}
                          </div>
                        </div>
                      </div>

                      <div className="flex shrink-0 items-center gap-2 pl-2">
                        <Button
                          size="sm"
                          variant={isCurrent ? "default" : "outline"}
                          className={`h-7 px-2.5 text-xs font-medium ${
                            isCurrent
                              ? "bg-indigo-600 text-white"
                              : "border-slate-300 text-slate-700 hover:bg-indigo-600 hover:text-white dark:border-slate-700 dark:text-slate-300"
                          }`}
                        >
                          {isCurrent ? "Connected" : "Connect"}
                          <ArrowRight className="ml-1 h-3 w-3" />
                        </Button>
                      </div>
                    </div>
                  )
                })
              )}
            </div>

            <DialogFooter className="flex items-center justify-between gap-2 pt-3 border-t border-slate-100 dark:border-slate-800 sm:justify-between">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={refreshDiscovery}
                disabled={isDiscovering}
                className="h-8 text-xs gap-1.5"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${isDiscovering ? "animate-spin" : ""}`} />
                Refresh Devices
              </Button>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => setIsConnectModalOpen(false)}
                className="h-8 text-xs text-slate-500"
              >
                Close
              </Button>
            </DialogFooter>
          </>
        ) : (
          /* Step 2: User Permission & Consent */
          <>
            <DialogHeader className="space-y-1 pb-1">
              <DialogTitle className="flex items-center gap-2 text-base font-bold text-slate-900 dark:text-slate-100">
                <Lock className="h-5 w-5 text-amber-500" />
                Permission & Monitoring Consent
              </DialogTitle>
              <DialogDescription className="text-xs text-slate-500 dark:text-slate-400">
                Confirm authorization to monitor network traffic for this device.
              </DialogDescription>
            </DialogHeader>

            {connectError && (
              <div className="rounded-lg border border-rose-300 bg-rose-50 p-2.5 text-xs text-rose-800 dark:border-rose-900 dark:bg-rose-950/40 dark:text-rose-300 flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 shrink-0 text-rose-600" />
                <span>{connectError}</span>
              </div>
            )}

            {selectedDevice && (
              <div className="space-y-3.5 py-1">
                {/* Target Device Summary Box */}
                <div className="rounded-xl border border-slate-200 bg-slate-50/70 p-3.5 dark:border-slate-800 dark:bg-slate-800/40 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                      Selected Target Device
                    </span>
                    <Badge variant="outline" className="text-[10px] font-mono">
                      {selectedDevice.ip}
                    </Badge>
                  </div>
                  <div className="flex items-center gap-3">
                    <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-indigo-600/10 text-indigo-600 dark:text-indigo-400">
                      <Laptop className="h-5 w-5" />
                    </div>
                    <div>
                      <p className="text-sm font-bold text-slate-900 dark:text-slate-100">
                        {selectedDevice.name}
                      </p>
                      <p className="text-xs text-slate-500 dark:text-slate-400 font-mono">
                        {selectedDevice.device_type} • MAC: {selectedDevice.mac || "Not Broadcast"}
                      </p>
                    </div>
                  </div>
                </div>

                {/* Explicit Consent Message Card */}
                <div className="rounded-xl border border-amber-300/80 bg-amber-50/80 p-3.5 text-xs text-amber-900 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-200 space-y-2">
                  <div className="flex items-center gap-1.5 font-bold text-amber-800 dark:text-amber-300">
                    <ShieldAlert className="h-4 w-4 shrink-0" />
                    <span>USER PERMISSION REQUIRED</span>
                  </div>
                  <p className="leading-relaxed">
                    You are about to monitor network activity associated with this device. Only continue if you have permission to monitor this device.
                  </p>
                </div>

                {/* Scope Notice */}
                <div className="rounded-lg border border-slate-200 bg-white p-3 text-xs text-slate-600 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-400 space-y-1">
                  <p className="font-semibold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                    <Activity className="h-3.5 w-3.5 text-indigo-600 dark:text-indigo-400" />
                    Global Monitoring Scope
                  </p>
                  <p className="text-[11px] leading-normal text-slate-500 dark:text-slate-400">
                    Once connected, the entire NetGuard application (Overview, Network Topology, Attack Forecasting, Traffic & Packets, and Threat Detection) will scope its live analysis to <strong>{selectedDevice.name}</strong> ({selectedDevice.ip}).
                  </p>
                </div>
              </div>
            )}

            <DialogFooter className="gap-2 pt-2 border-t border-slate-100 dark:border-slate-800">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setStep("discover")}
                disabled={isSubmitting}
                className="h-8 text-xs"
              >
                Cancel / Back
              </Button>
              <Button
                type="button"
                size="sm"
                onClick={handleConfirmConnect}
                disabled={isSubmitting}
                className="h-8 text-xs bg-emerald-600 hover:bg-emerald-700 text-white font-semibold gap-1.5 shadow-sm"
              >
                {isSubmitting ? (
                  <>
                    <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                    Connecting...
                  </>
                ) : (
                  <>
                    <ShieldCheck className="h-3.5 w-3.5" />
                    Connect & Monitor
                  </>
                )}
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  )
}
