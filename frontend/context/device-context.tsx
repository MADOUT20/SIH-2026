"use client"

import React, { createContext, useContext, useState, useEffect, useCallback } from "react"
import {
  discoverDevices,
  getActiveDevice,
  connectDevice as apiConnectDevice,
  disconnectActiveDevice,
  getDeviceTraffic,
  getDeviceThreatAssessment,
  normalizeDevice,
  type DiscoveredDevice,
  type NetworkDevice,
  type DeviceItem,
  type DeviceTrafficDetails,
  type DeviceThreatAssessment,
} from "@/lib/api"

export interface DeviceContextType {
  connectedDevice: NetworkDevice | null
  connectedDeviceId: string | null
  isMonitoring: boolean
  discoveredDevices: NetworkDevice[]
  isDiscovering: boolean
  discoveryError: string | null
  isConnectModalOpen: boolean
  setIsConnectModalOpen: (open: boolean) => void
  openConnectModal: () => void
  refreshDiscovery: () => Promise<void>
  connectDevice: (device: DiscoveredDevice | DeviceItem | NetworkDevice, consent: boolean) => Promise<boolean>
  disconnectDevice: () => Promise<boolean>
  activeTraffic: DeviceTrafficDetails | null
  activeAssessment: DeviceThreatAssessment | null
  refreshActiveDeviceTelemetry: () => Promise<void>
  appMode: "live" | "demo"
}

const DeviceContext = createContext<DeviceContextType | undefined>(undefined)

const DASHBOARD_REFRESH_EVENT = "netguard:dashboard-refresh"

export function DeviceProvider({ children }: { children: React.ReactNode }) {
  const [appMode, setAppMode] = useState<"live" | "demo">("live")
  const [connectedDevice, setConnectedDevice] = useState<NetworkDevice | null>(null)
  const [discoveredDevices, setDiscoveredDevices] = useState<NetworkDevice[]>([])
  const [isDiscovering, setIsDiscovering] = useState(false)
  const [discoveryError, setDiscoveryError] = useState<string | null>(null)
  const [isConnectModalOpen, setIsConnectModalOpen] = useState(false)
  const [activeTraffic, setActiveTraffic] = useState<DeviceTrafficDetails | null>(null)
  const [activeAssessment, setActiveAssessment] = useState<DeviceThreatAssessment | null>(null)

  // Track appMode from localStorage and events
  useEffect(() => {
    if (typeof window !== "undefined") {
      const stored = (localStorage.getItem("netguard_app_mode") as "live" | "demo") || "live"
      setAppMode(stored)

      const handleModeChange = (e: any) => {
        if (e.detail?.mode) {
          setAppMode(e.detail.mode)
        }
      }

      window.addEventListener("netguard:mode-change", handleModeChange)
      return () => window.removeEventListener("netguard:mode-change", handleModeChange)
    }
  }, [])

  // Fetch active device from backend
  const refreshActiveDevice = useCallback(async () => {
    try {
      const res = await getActiveDevice(appMode)
      if (res.has_active_device && res.device) {
        setConnectedDevice(res.device)
      } else {
        setConnectedDevice(null)
        setActiveTraffic(null)
        setActiveAssessment(null)
      }
    } catch (err) {
      console.error("Failed to load active connected device:", err)
    }
  }, [appMode])

  // Fetch telemetry for currently connected device
  const refreshActiveDeviceTelemetry = useCallback(async () => {
    if (!connectedDevice) return
    const targetId = connectedDevice.id || connectedDevice.ip
    try {
      const [traffic, assessment] = await Promise.all([
        getDeviceTraffic(targetId, appMode).catch(() => null),
        getDeviceThreatAssessment(targetId, appMode).catch(() => null),
      ])
      if (traffic) setActiveTraffic(traffic)
      if (assessment) setActiveAssessment(assessment)
    } catch (err) {
      console.warn("Telemetry polling transient error:", err)
    }
  }, [connectedDevice, appMode])

  // Discover local / nearby devices
  const refreshDiscovery = useCallback(async () => {
    setIsDiscovering(true)
    setDiscoveryError(null)
    try {
      const res = await discoverDevices(appMode)
      setDiscoveredDevices(res.devices || [])
      setConnectedDevice(res.active_device || null)
    } catch (err: any) {
      console.error("Device discovery error:", err)
      setDiscoveryError(err?.message || "Failed to discover local network devices.")
    } finally {
      setIsDiscovering(false)
    }
  }, [appMode])

  // Initial load and periodic refresh
  useEffect(() => {
    refreshActiveDevice()
    refreshDiscovery()
  }, [refreshActiveDevice, refreshDiscovery])

  useEffect(() => {
    if (connectedDevice) {
      refreshActiveDeviceTelemetry()
      const interval = setInterval(refreshActiveDeviceTelemetry, 4000)
      return () => clearInterval(interval)
    }
  }, [connectedDevice, refreshActiveDeviceTelemetry])

  // Listen to global dashboard refresh event
  useEffect(() => {
    const handleRefresh = () => {
      refreshActiveDevice()
      refreshActiveDeviceTelemetry()
    }
    window.addEventListener(DASHBOARD_REFRESH_EVENT, handleRefresh)
    return () => window.removeEventListener(DASHBOARD_REFRESH_EVENT, handleRefresh)
  }, [refreshActiveDevice, refreshActiveDeviceTelemetry])

  const openConnectModal = useCallback(() => {
    setIsConnectModalOpen(true)
    refreshDiscovery()
  }, [refreshDiscovery])

  // Connect device with user consent
  const connectDevice = useCallback(
    async (device: DiscoveredDevice | DeviceItem, consent: boolean): Promise<boolean> => {
      if (!consent) {
        throw new Error("Explicit user consent is required before connecting and monitoring this device.")
      }

      try {
        const res = await apiConnectDevice({
          device_id: device.id,
          name: device.name,
          ip: device.ip,
          mac: device.mac || undefined,
          device_type: device.device_type,
          description: device.description || undefined,
          consent: true,
          mode: appMode,
        })

        if (res.device) {
          // Immediately fetch active device details
          const activeRes = await getActiveDevice(appMode)
          setConnectedDevice(activeRes.device || res.device)
        }

        if (typeof window !== "undefined") {
          window.dispatchEvent(new Event(DASHBOARD_REFRESH_EVENT))
        }

        setIsConnectModalOpen(false)
        return true
      } catch (err) {
        console.error("Connect device failed:", err)
        refreshDiscovery()
        throw err
      }
    },
    [appMode]
  )

  // Disconnect active device
  const disconnectDevice = useCallback(async (): Promise<boolean> => {
    try {
      await disconnectActiveDevice()
      setConnectedDevice(null)
      setActiveTraffic(null)
      setActiveAssessment(null)

      if (typeof window !== "undefined") {
        window.dispatchEvent(new Event(DASHBOARD_REFRESH_EVENT))
      }
      return true
    } catch (err) {
      console.error("Disconnect device failed:", err)
      return false
    }
  }, [])

  return (
    <DeviceContext.Provider
      value={{
        connectedDevice,
        connectedDeviceId: connectedDevice?.id || null,
        isMonitoring: connectedDevice !== null,
        discoveredDevices,
        isDiscovering,
        discoveryError,
        isConnectModalOpen,
        setIsConnectModalOpen,
        openConnectModal,
        refreshDiscovery,
        connectDevice,
        disconnectDevice,
        activeTraffic,
        activeAssessment,
        refreshActiveDeviceTelemetry,
        appMode,
      }}
    >
      {children}
    </DeviceContext.Provider>
  )
}

export function useDevice() {
  const context = useContext(DeviceContext)
  if (!context) {
    throw new Error("useDevice must be used within a DeviceProvider")
  }
  return context
}
