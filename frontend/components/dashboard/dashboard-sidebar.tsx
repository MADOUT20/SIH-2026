"use client"
// Dashboard navigation sidebar for desktop and mobile layouts.

import { useState } from "react"
import {
  Shield,
  LayoutDashboard,
  Network,
  Activity,
  Search,
  ShieldAlert,
  Settings,
  Layers,
  Bug,
  BrainCircuit,
  TrendingUp,
  UploadCloud,
  ChevronLeft,
  ChevronRight,
  CheckCircle2,
} from "lucide-react"
import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { useIsMobile } from "@/components/ui/use-mobile"

const navItems = [
  { icon: LayoutDashboard, label: "Overview", id: "overview" },
  { icon: Network, label: "Network Topology", id: "topology" },
  { icon: TrendingUp, label: "Attack Forecasting", id: "forecasting" },
  { icon: UploadCloud, label: "Offline Workbench (PCAP/CSV)", id: "workbench" },
  { icon: Layers, label: "MITRE ATT&CK Matrix", id: "mitre" },
  { icon: Activity, label: "Traffic & Packets", id: "packets" },
  { icon: BrainCircuit, label: "ML Benchmarks", id: "ml" },
  { icon: Bug, label: "Website Scanner", id: "scanner" },
  { icon: ShieldAlert, label: "Threat Detection", id: "threats" },
  { icon: Settings, label: "Settings", id: "settings" },
]

interface DashboardSidebarProps {
  activeTab: string
  onTabChange: (tab: string) => void
  mobileOpen?: boolean
  onMobileOpenChange?: (open: boolean) => void
}

export function DashboardSidebar({
  activeTab,
  onTabChange,
  mobileOpen = false,
  onMobileOpenChange,
}: DashboardSidebarProps) {
  const [collapsed, setCollapsed] = useState(false)
  const isMobile = useIsMobile()

  const handleTabChange = (tab: string) => {
    onTabChange(tab)
    onMobileOpenChange?.(false)
  }

  const navigationItems = (
    <nav className="flex-1 space-y-1 p-3">
      {navItems.map((item) => {
        const isActive = activeTab === item.id
        const button = (
          <button
            key={item.id}
            onClick={() => handleTabChange(item.id)}
            className={cn(
              "flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left text-sm transition-colors",
              isActive
                ? "bg-sidebar-accent text-sidebar-primary font-medium"
                : "text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
            )}
          >
            <item.icon className="h-4.5 w-4.5 shrink-0" />
            {(!collapsed || isMobile) && <span>{item.label}</span>}
          </button>
        )

        if (collapsed && !isMobile) {
          return (
            <Tooltip key={item.id}>
              <TooltipTrigger asChild>{button}</TooltipTrigger>
              <TooltipContent side="right" className="bg-popover text-popover-foreground">
                {item.label}
              </TooltipContent>
            </Tooltip>
          )
        }

        return button
      })}
    </nav>
  )

  if (isMobile) {
    return (
      <Sheet open={mobileOpen} onOpenChange={onMobileOpenChange}>
        <SheetContent
          side="left"
          className="w-[86vw] max-w-[22rem] border-sidebar-border bg-sidebar p-0 text-sidebar-foreground"
        >
          <SheetHeader className="border-b border-sidebar-border px-4 py-4 text-left">
            <div className="flex items-center gap-3">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary">
                <Shield className="h-5 w-5 text-primary-foreground" />
              </div>
              <div>
                <SheetTitle className="text-base text-sidebar-foreground">NetGuard</SheetTitle>
                <SheetDescription className="text-xs text-sidebar-foreground/70">
                  Security Operations Center
                </SheetDescription>
              </div>
            </div>
          </SheetHeader>

          <div className="flex h-full flex-col">
            {navigationItems}
            <div className="border-t border-sidebar-border p-3 text-xs text-muted-foreground flex items-center justify-between">
              <span className="flex items-center gap-1.5">
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
                Local Engine Online
              </span>
              <span>v2.0</span>
            </div>
          </div>
        </SheetContent>
      </Sheet>
    )
  }

  return (
    <TooltipProvider delayDuration={0}>
      <aside
        className={cn(
          "flex flex-col border-r border-sidebar-border bg-sidebar transition-all duration-200",
          collapsed ? "w-16" : "w-60"
        )}
      >
        {/* Logo */}
        <div className="flex h-16 items-center gap-3 border-b border-sidebar-border px-4">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary">
            <Shield className="h-5 w-5 text-primary-foreground" />
          </div>
          {!collapsed && (
            <span className="text-lg font-bold text-sidebar-foreground">NetGuard</span>
          )}
        </div>

        {navigationItems}

        {/* System Status Footer */}
        <div className="border-t border-sidebar-border p-3 text-xs text-muted-foreground">
          {!collapsed && (
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-1.5 text-emerald-500 font-medium">
                <CheckCircle2 className="h-3.5 w-3.5" />
                System Active
              </span>
              <span>Local</span>
            </div>
          )}
        </div>

        {/* Collapse Toggle */}
        <div className="border-t border-sidebar-border p-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setCollapsed(!collapsed)}
            className="w-full justify-center text-sidebar-foreground hover:bg-sidebar-accent"
          >
            {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
          </Button>
        </div>
      </aside>
    </TooltipProvider>
  )
}
