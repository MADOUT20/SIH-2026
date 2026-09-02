"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { ScrollArea } from "@/components/ui/scroll-area"
import { 
  ShieldAlert, 
  ExternalLink, 
  RefreshCw, 
  Layers, 
  AlertTriangle, 
  CheckCircle, 
  ArrowRight,
  Info,
  Flame,
  Activity,
  Zap,
  Trash2,
  Bug
} from "lucide-react"
import { 
  getMitreStages, 
  getMitreTaxonomy,
  simulateAttackScenario,
  clearSimulation,
  type AttackChainResponse, 
  type AttackChainStage,
  type AttackChainThreatItem 
} from "@/lib/api"

const DASHBOARD_REFRESH_EVENT = "netguard:dashboard-refresh"

function emitDashboardRefresh() {
  if (typeof window !== "undefined") {
    window.dispatchEvent(new Event(DASHBOARD_REFRESH_EVENT))
  }
}

export function MitreAttackMatrix() {
  const [attackChain, setAttackChain] = useState<AttackChainResponse | null>(null)
  const [taxonomy, setTaxonomy] = useState<any>(null)
  const [selectedStage, setSelectedStage] = useState<AttackChainStage | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")
  const [currentMode, setCurrentMode] = useState<"live" | "demo">("live")

  useEffect(() => {
    if (typeof window !== "undefined") {
      const stored = (localStorage.getItem("netguard_app_mode") as "live" | "demo") || "live"
      setCurrentMode(stored)

      const handleModeChange = (e: any) => {
        if (e.detail?.mode) {
          setCurrentMode(e.detail.mode)
        }
      }

      window.addEventListener("netguard:mode-change", handleModeChange)
      return () => window.removeEventListener("netguard:mode-change", handleModeChange)
    }
  }, [])

  const fetchData = async () => {
    try {
      setLoading(true)
      const [stagesData, taxonomyData] = await Promise.all([
        getMitreStages(currentMode),
        getMitreTaxonomy(),
      ])
      setAttackChain(stagesData)
      setTaxonomy(taxonomyData)
      
      // Auto-select the first active stage if none selected
      if (stagesData.progression && stagesData.progression.length > 0) {
        setSelectedStage((curr) => curr || stagesData.progression[0])
      } else if (stagesData.all_stages && stagesData.all_stages.length > 0) {
        setSelectedStage((curr) => curr || stagesData.all_stages[0])
      }
      setError("")
    } catch (err: any) {
      console.error("Failed to fetch MITRE ATT&CK data:", err)
      setError("Failed to load MITRE ATT&CK matrix")
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    let isMounted = true
    const load = async () => {
      try {
        const [stagesData, taxonomyData] = await Promise.all([
          getMitreStages(currentMode),
          getMitreTaxonomy(),
        ])
        if (isMounted) {
          setAttackChain(stagesData)
          setTaxonomy(taxonomyData)
          if (stagesData.progression && stagesData.progression.length > 0) {
            setSelectedStage((curr) => curr || stagesData.progression[0])
          } else if (stagesData.all_stages && stagesData.all_stages.length > 0) {
            setSelectedStage((curr) => curr || stagesData.all_stages[0])
          }
          setError("")
          setLoading(false)
        }
      } catch (err: any) {
        if (isMounted) {
          console.error("Failed to fetch MITRE ATT&CK data:", err)
          setError("Failed to load MITRE ATT&CK matrix")
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
  }, [currentMode])

  const allStages = attackChain?.all_stages || []
  const activeStagesCount = attackChain?.total_active_stages || 0
  const highestStageNumber = attackChain?.highest_stage_number || 0
  const progressionPercent = attackChain?.progression_percent || 0

  const handleSimulateAttack = async (type: "multi_stage" | "trojan" = "multi_stage") => {
    try {
      setLoading(true)
      const res = await simulateAttackScenario(type)
      setAttackChain(res.attack_chain)
      if (res.attack_chain.progression && res.attack_chain.progression.length > 0) {
        setSelectedStage(res.attack_chain.progression[0])
      }
      emitDashboardRefresh()
    } catch (err) {
      console.error("Failed to simulate attack:", err)
    } finally {
      setLoading(false)
    }
  }

  const handleClearSimulation = async () => {
    try {
      setLoading(true)
      const res = await clearSimulation()
      setAttackChain(res.attack_chain)
      if (res.attack_chain.all_stages && res.attack_chain.all_stages.length > 0) {
        setSelectedStage(res.attack_chain.all_stages[0])
      }
      emitDashboardRefresh()
    } catch (err) {
      console.error("Failed to clear simulation:", err)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Header Overview Card */}
      <Card className="border-border bg-gradient-to-r from-slate-900 via-indigo-950 to-slate-900 text-white shadow-xl">
        <CardHeader className="pb-3">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="space-y-1">
              <div className="flex items-center gap-2 flex-wrap">
                <Badge variant="outline" className={currentMode === "live" ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/40 font-bold" : "bg-amber-500/20 text-amber-300 border-amber-500/40 font-bold"}>
                  {currentMode === "live" ? "🟢 LIVE MITRE MAPPING" : "🟣 DEMO ATTACK SCENARIO"}
                </Badge>
                <Badge className="bg-indigo-600 hover:bg-indigo-700 text-xs px-2.5 py-0.5">
                  MITRE ATT&CK Enterprise v15.1
                </Badge>
                {activeStagesCount > 0 ? (
                  <Badge variant="destructive" className="animate-pulse flex items-center gap-1">
                    <Flame className="w-3 h-3" />
                    {activeStagesCount} Active Attack Stage{activeStagesCount === 1 ? "" : "s"}
                  </Badge>
                ) : (
                  <Badge className="bg-emerald-600 text-white flex items-center gap-1">
                    <CheckCircle className="w-3 h-3" />
                    Kill-Chain Inactive
                  </Badge>
                )}
              </div>
              <CardTitle className="text-xl font-bold tracking-tight text-white flex items-center gap-2 mt-1">
                <Layers className="w-5 h-5 text-indigo-400" />
                MITRE ATT&CK Stage Mapping & Kill-Chain Matrix
              </CardTitle>
              <CardDescription className="text-slate-300 text-xs sm:text-sm">
                Real-time mapping of network anomalies, malware vectors, trojans, and web packets across all 14 attack stages.
              </CardDescription>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Button 
                size="sm" 
                onClick={() => handleSimulateAttack("multi_stage")}
                className="bg-red-600 hover:bg-red-700 text-white text-xs font-semibold shadow-md shadow-red-600/30"
              >
                <Zap className="w-3.5 h-3.5 mr-1" />
                Simulate Attack Chain
              </Button>
              <Button 
                size="sm" 
                variant="outline"
                onClick={() => handleSimulateAttack("trojan")}
                className="border-purple-500 bg-purple-950/60 text-purple-200 hover:bg-purple-900 text-xs font-semibold"
              >
                <Bug className="w-3.5 h-3.5 mr-1" />
                Simulate Trojan
              </Button>
              {activeStagesCount > 0 && (
                <Button 
                  size="sm" 
                  variant="outline"
                  onClick={handleClearSimulation}
                  className="border-slate-700 bg-slate-800/80 text-slate-300 hover:bg-slate-700 text-xs"
                >
                  <Trash2 className="w-3.5 h-3.5 mr-1" />
                  Clear
                </Button>
              )}
              <Button 
                size="sm" 
                variant="outline" 
                onClick={fetchData} 
                className="border-slate-700 bg-slate-800/80 text-slate-200 hover:bg-slate-700 hover:text-white"
              >
                <RefreshCw className={`w-4 h-4 mr-1.5 ${loading ? "animate-spin" : ""}`} />
                Refresh
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4 pt-1">
          {/* Progression Bar */}
          <div className="space-y-1.5 bg-slate-800/60 p-3.5 rounded-xl border border-slate-700/50">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-300 font-medium flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-indigo-400" />
                Attack Kill-Chain Penetration Depth:
              </span>
              <span className="font-bold text-indigo-300">
                {highestStageNumber > 0 ? `Stage ${highestStageNumber} / 14 (${progressionPercent}%)` : "0% (No Penetration)"}
              </span>
            </div>
            <div className="w-full bg-slate-950/80 rounded-full h-3 overflow-hidden p-0.5 border border-slate-700">
              <div 
                className="h-full rounded-full transition-all duration-500 bg-gradient-to-r from-sky-400 via-indigo-500 to-red-500 shadow-sm"
                style={{ width: `${Math.max(progressionPercent, highestStageNumber > 0 ? 8 : 0)}%` }}
              />
            </div>
            <div className="flex justify-between text-[10px] text-slate-400 px-0.5 pt-0.5">
              <span>Stage 1: Reconnaissance</span>
              <span>Stage 7: Evasion</span>
              <span>Stage 14: Impact</span>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* 14 Stages Timeline Grid */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-200 flex items-center gap-2">
            <Layers className="w-4 h-4 text-indigo-500" />
            14-Stage ATT&CK Tactics Matrix
          </h3>
          <span className="text-xs text-slate-500">Click any stage card to inspect technique details and mitigations</span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-7 gap-2">
          {allStages.map((stage) => {
            const isSelected = selectedStage?.stage_number === stage.stage_number
            const hasThreats = stage.count > 0

            return (
              <div
                key={stage.stage_number}
                onClick={() => setSelectedStage(stage)}
                className={`cursor-pointer rounded-xl p-2.5 transition-all text-left relative border flex flex-col justify-between ${
                  isSelected
                    ? "ring-2 ring-indigo-500 bg-indigo-50/90 dark:bg-indigo-950/50 border-indigo-300 dark:border-indigo-700 shadow-md"
                    : hasThreats
                    ? "bg-red-50/80 dark:bg-red-950/30 border-red-200 dark:border-red-800 hover:border-red-400"
                    : "bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700"
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span 
                      className="text-[10px] font-bold px-1.5 py-0.5 rounded"
                      style={{ 
                        backgroundColor: `${stage.color}20`, 
                        color: stage.color 
                      }}
                    >
                      Stage {stage.stage_number}
                    </span>
                    {hasThreats ? (
                      <span className="flex h-2 w-2 relative">
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
                        <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500"></span>
                      </span>
                    ) : null}
                  </div>
                  <p className="text-xs font-semibold text-slate-900 dark:text-slate-100 truncate" title={stage.tactic_name}>
                    {stage.tactic_name}
                  </p>
                  <p className="text-[10px] text-slate-500 font-mono mt-0.5">{stage.tactic_id}</p>
                </div>

                <div className="mt-2 pt-1 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between">
                  <span className="text-[10px] text-slate-500">Threats:</span>
                  <Badge 
                    variant={hasThreats ? "destructive" : "outline"} 
                    className={`text-[10px] px-1.5 py-0 h-4 font-bold ${
                      !hasThreats ? "text-slate-400 border-slate-200 dark:border-slate-800" : ""
                    }`}
                  >
                    {stage.count}
                  </Badge>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Selected Stage Detail Inspection Panel */}
      {selectedStage && (
        <Card className="border-indigo-200 dark:border-indigo-900 shadow-md">
          <CardHeader className="pb-3 border-b border-slate-100 dark:border-slate-800">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <Badge 
                    style={{ backgroundColor: selectedStage.color, color: "#ffffff" }}
                    className="font-bold text-xs"
                  >
                    Stage {selectedStage.stage_number}
                  </Badge>
                  <span className="text-xs font-mono text-slate-500">[{selectedStage.tactic_id}]</span>
                  {selectedStage.count > 0 && (
                    <Badge variant="destructive" className="text-xs">
                      {selectedStage.count} Active Finding{selectedStage.count === 1 ? "" : "s"}
                    </Badge>
                  )}
                </div>
                <CardTitle className="text-lg font-bold text-slate-900 dark:text-slate-100">
                  {selectedStage.tactic_name}
                </CardTitle>
                <CardDescription className="text-xs sm:text-sm text-slate-600 dark:text-slate-400">
                  {selectedStage.description || "MITRE ATT&CK tactical kill-chain stage."}
                </CardDescription>
              </div>

              <a
                href={`https://attack.mitre.org/tactics/${selectedStage.tactic_id}/`}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 text-xs font-medium text-indigo-600 dark:text-indigo-400 hover:underline"
              >
                View in MITRE Matrix <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          </CardHeader>
          <CardContent className="pt-4 space-y-4">
            {/* Active Threats in this stage */}
            <div>
              <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-2 flex items-center gap-1.5">
                <ShieldAlert className="w-4 h-4 text-red-500" />
                Active Threats Mapped to this Stage ({selectedStage.threats.length})
              </h4>

              {selectedStage.threats.length === 0 ? (
                <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-900/60 border border-dashed border-slate-200 dark:border-slate-800 text-center">
                  <CheckCircle className="w-5 h-5 text-emerald-500 mx-auto mb-1" />
                  <p className="text-xs font-medium text-slate-700 dark:text-slate-300">
                    No active threats currently observed at Stage {selectedStage.stage_number} ({selectedStage.tactic_name}).
                  </p>
                  <p className="text-[11px] text-slate-500 mt-0.5">
                    NetGuard packet inspection and proxy monitoring are actively patrolling this stage.
                  </p>
                </div>
              ) : (
                <div className="grid gap-2 sm:grid-cols-2">
                  {selectedStage.threats.map((threat, idx) => (
                    <div 
                      key={threat.id || idx}
                      className="p-3 rounded-xl border border-red-200 dark:border-red-900 bg-red-50/50 dark:bg-red-950/20 space-y-1.5"
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-slate-900 dark:text-slate-100">
                          {threat.type.replace(/_/g, " ")}
                        </span>
                        <Badge 
                          variant={threat.severity === "CRITICAL" ? "destructive" : "default"}
                          className={
                            threat.severity === "HIGH" 
                              ? "bg-orange-600" 
                              : threat.severity === "MEDIUM" 
                              ? "bg-yellow-600" 
                              : "bg-blue-600"
                          }
                        >
                          {threat.severity}
                        </Badge>
                      </div>

                      <div className="text-xs text-slate-600 dark:text-slate-400 flex items-center gap-1.5 font-mono">
                        <span className="font-semibold text-indigo-600 dark:text-indigo-400">
                          {threat.technique_id}
                        </span>
                        <span>•</span>
                        <span>{threat.technique_name}</span>
                      </div>

                      {threat.destination_host && (
                        <p className="text-xs text-slate-700 dark:text-slate-300 font-medium">
                          Target Host: <span className="font-mono text-red-600 dark:text-red-400">{threat.destination_host}</span>
                        </p>
                      )}

                      {threat.source_ip && (
                        <p className="text-[11px] text-slate-500">
                          Source Device: {threat.source_ip}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Mapped Techniques in this Stage */}
            {taxonomy?.techniques && (
              <div className="border-t border-slate-100 dark:border-slate-800 pt-3">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-2 flex items-center gap-1.5">
                  <Info className="w-4 h-4 text-indigo-500" />
                  Standard MITRE ATT&CK Techniques, Detection Logic & Mitigations for {selectedStage.tactic_name}
                </h4>

                <div className="grid gap-2.5 sm:grid-cols-2 lg:grid-cols-3">
                  {Object.entries(taxonomy.techniques)
                    .filter(([_, t]: [string, any]) => t.stage_number === selectedStage.stage_number || t.tactic_id === selectedStage.tactic_id)
                    .map(([key, tech]: [string, any]) => (
                      <div 
                        key={key}
                        className="p-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-2 text-xs shadow-xs"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-indigo-600 dark:text-indigo-400 font-mono text-xs">
                            {tech.technique_id}
                          </span>
                          <a 
                            href={tech.reference_url} 
                            target="_blank" 
                            rel="noreferrer" 
                            className="text-slate-400 hover:text-indigo-600 inline-flex items-center gap-1 text-[11px]"
                          >
                            MITRE <ExternalLink className="w-3 h-3" />
                          </a>
                        </div>

                        <p className="font-semibold text-slate-800 dark:text-slate-200 text-xs">
                          {tech.technique_name}
                        </p>

                        <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-relaxed">
                          {tech.description}
                        </p>

                        {/* Detection Logic */}
                        <div className="pt-1.5 border-t border-slate-100 dark:border-slate-800/80 space-y-1 text-[11px]">
                          <div className="text-slate-600 dark:text-slate-400">
                            <strong className="text-slate-700 dark:text-slate-300">Detection Logic:</strong>{" "}
                            {tech.detection || "Monitored via NetGuard packet flow signatures, anomalous port access, and 27-feature temporal LSTM world model."}
                          </div>
                          <div className="text-emerald-700 dark:text-emerald-400">
                            <strong>Recommended Response:</strong>{" "}
                            {tech.mitigation || "Enforce zero-trust proxy block rule, isolate destination host, and alert network administrator."}
                          </div>
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}
