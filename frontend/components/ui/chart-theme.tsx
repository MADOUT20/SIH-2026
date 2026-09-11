"use client"

import React, { useSyncExternalStore } from "react"
import { useTheme } from "next-themes"

// Hook to check if mounted on client to prevent SSR hydration mismatches
const subscribe = () => () => {}
export function useIsMounted() {
  return useSyncExternalStore(
    subscribe,
    () => true,
    () => false,
  )
}

export interface CustomTooltipProps {
  active?: boolean
  payload?: Array<{
    name?: string
    value?: number | string
    color?: string
    dataKey?: string
    payload?: any
  }>
  label?: string
  valuePrefix?: string
  valueSuffix?: string
  title?: string
  formatter?: (value: any, name: string) => [string, string]
}

export function CustomChartTooltip({
  active,
  payload,
  label,
  valuePrefix = "",
  valueSuffix = "",
  title,
  formatter,
}: CustomTooltipProps) {
  if (!active || !payload || payload.length === 0) {
    return null
  }

  return (
    <div className="rounded-lg border border-slate-200 bg-white/95 px-3 py-2 text-xs text-slate-900 shadow-xl backdrop-blur-md transition-all dark:border-slate-800 dark:bg-slate-900/95 dark:text-slate-100 min-w-[140px]">
      {(title || label) && (
        <div className="mb-1.5 border-b border-slate-100 pb-1 font-semibold text-slate-700 dark:border-slate-800/80 dark:text-slate-300">
          {title || label}
        </div>
      )}
      <div className="space-y-1">
        {payload.map((item, idx) => {
          let displayName = item.name || item.dataKey || "Value"
          let displayVal = `${valuePrefix}${item.value}${valueSuffix}`

          if (formatter && item.value !== undefined) {
            const [fVal, fName] = formatter(item.value, displayName)
            displayVal = fVal
            displayName = fName
          }

          const dotColor = item.color || "#6366f1"

          return (
            <div key={idx} className="flex items-center justify-between gap-4 font-mono">
              <div className="flex items-center gap-1.5 font-sans text-slate-600 dark:text-slate-400">
                <span
                  className="inline-block h-2 w-2 rounded-full shrink-0"
                  style={{ backgroundColor: dotColor }}
                />
                <span className="truncate max-w-[160px]">{displayName}</span>
              </div>
              <span className="font-bold text-slate-900 dark:text-slate-100">
                {displayVal}
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// Chart theme configuration tokens for dark and light modes
export function useChartTheme() {
  const { resolvedTheme } = useTheme()
  const isDark = resolvedTheme === "dark"

  return {
    isDark,
    gridStroke: isDark ? "rgba(255, 255, 255, 0.08)" : "rgba(0, 0, 0, 0.06)",
    gridStrokeDasharray: "3 3",
    axisStroke: isDark ? "rgba(255, 255, 255, 0.3)" : "rgba(0, 0, 0, 0.35)",
    tickStroke: isDark ? "rgba(255, 255, 255, 0.45)" : "rgba(0, 0, 0, 0.55)",
    tickFontSize: 11,
    fontFamily: "var(--font-sans, inherit)",
    colors: {
      primary: isDark ? "#38bdf8" : "#0284c7",       // Sky
      secondary: isDark ? "#818cf8" : "#4f46e5",     // Indigo
      success: isDark ? "#34d399" : "#059669",       // Emerald
      warning: isDark ? "#fbbf24" : "#d97706",       // Amber
      danger: isDark ? "#f43f5e" : "#e11d48",        // Rose
      neutral: isDark ? "#94a3b8" : "#64748b",       // Slate
    },
  }
}
