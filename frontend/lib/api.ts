// Central frontend API client used to talk to the FastAPI backend.
// API utility functions for the NetGuard backend.

const DEFAULT_HEADERS = {
  "Content-Type": "application/json",
}

export interface TrafficStats {
  total_packets: number
  total_bytes: number
  average_packet_size: number
  packets_per_second: number
  time_range?: string
  timestamp?: string
}

export interface ProtocolTraffic {
  count: number
  bytes: number
  percentage: number
}

export interface TrafficProtocolResponse {
  protocols: Record<string, ProtocolTraffic>
  total_packets: number
  total_bytes: number
  timestamp: string
}

export interface PacketStatistics {
  total_packets: number
  total_bytes: number
  average_packet_size: number
  protocols: Record<string, number>
  top_ports: Record<string, number>
  stored_packets: number
}

export interface StartCaptureResponse {
  capture_id: string
  status: string
  interface: string
  packets_captured: number
  count: number
  timeout: number
  timestamp: string
}

export interface MitreMapping {
  threat_type?: string
  tactic_id: string
  tactic_name: string
  technique_id: string
  technique_name: string
  sub_technique?: string
  stage_number: number
  stage_name: string
  stage_label?: string
  stage_description?: string
  color: string
  category?: string
  description: string
  mitigation: string
  reference_url: string
  secondary_tactic?: {
    tactic_id: string
    tactic_name: string
    technique_id: string
    technique_name: string
  }
}

export interface TopologyNode {
  id: string
  label: string
  ip: string
  role: string
  type?: string
  device_type?: string
  status: string
  is_local: boolean
  is_compromised?: boolean
  packets_in?: number
  packets_out?: number
  packet_count?: number
  total_bytes: number
  protocols: string[]
  ports?: number[]
  threat_level?: string
  os_fingerprint?: string
  last_activity?: string
  is_demo?: boolean
}

export interface TopologyLink {
  id?: string
  source: string
  target: string
  protocol: string
  port?: number
  ports?: number[]
  packet_count: number
  byte_count: number
  direction?: string
  has_reverse_flow?: boolean
  status?: string
  recent_activity?: string
  is_threat?: boolean
  threat_description?: string
  is_attack_path?: boolean
  label?: string
}

export interface NetworkTopologyResponse {
  mode: "live" | "demo"
  is_demo: boolean
  origin: string
  nodes: TopologyNode[]
  links: TopologyLink[]
  total_devices: number
  total_connections?: number
  total_links?: number
  captured_packets_analyzed?: number
  summary?: string
  message?: string
  timestamp: string
}

export interface FeatureAttributionItem {
  feature_name: string
  display_name: string
  category: string
  importance: number
  contribution_percent: string
  raw_gradient: number
  direction: string
  risk_impact: string
  description: string
  rank: number
}

export interface PacketExplanationResponse {
  status: string
  method: string
  model_name: string
  explainability_model: string
  disclaimer: string
  predicted_stage: string
  current_risk_score: number
  packet_metadata: {
    source_ip?: string
    dest_ip?: string
    dest_port?: number
    source_port?: number
    protocol?: string
    size_bytes?: number
    flags?: string[]
  }
  top_contributing_features: FeatureAttributionItem[]
  analysis_summary: string
  evaluated_feature_count: number
  timestamp: string
}

export interface AttackChainThreatItem {
  id?: string
  type: string
  technique_id: string
  technique_name: string
  stage_name?: string
  stage_number?: number
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
  source_ip?: string
  destination_host?: string
  timestamp?: string
}

export interface AttackChainStage {
  stage_number: number
  tactic_id: string
  tactic_name: string
  stage_label: string
  description?: string
  color: string
  count: number
  threats: AttackChainThreatItem[]
}

export interface AttackChainResponse {
  total_active_stages: number
  highest_stage_number?: number
  progression_percent?: number
  progression: AttackChainStage[]
  all_stages: AttackChainStage[]
  timestamp: string
}

export interface UrlScanWarning {
  title: string
  headline: string
  recommendation: string
  prevention_steps?: string[]
  badge_severity?: string
}

export interface UrlScanSignal {
  name: string
  category: string
  severity: string
  weight: number
  description: string
}

export interface UrlScanResponse {
  url: string
  domain: string
  path?: string
  is_malicious: boolean
  threat_type: string
  threat_category: string
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "SAFE"
  risk_level?: "Clean" | "Low Risk" | "Medium Risk" | "High Risk" | "Critical"
  threat_score: number
  confidence_percent: number
  contributing_signals?: UrlScanSignal[]
  mitre_mapping: MitreMapping
  warning: UrlScanWarning
  evidence: string[]
  scan_timestamp: string
  offline_capable?: boolean
  engine?: string
}

export interface MLPredictionModelResult {
  prediction: "MALICIOUS" | "BENIGN"
  threat_probability: number
  is_anomaly: boolean
  attack_stage?: string
  stage_name?: string
  stage_number?: number
  technique_id?: string
  technique_name?: string
}

export interface MLPredictionResponse {
  logistic_regression: MLPredictionModelResult
  ai_ensemble: MLPredictionModelResult
  mitre_attack_stage?: string
  mitre_stage_name?: string
  mitre_stage_number?: number
  mitre_technique?: string
  mitre_mapping?: MitreMapping
  warning?: {
    is_alert: boolean
    title: string
    summary: string
  }
  agreement: boolean
  features_extracted: Record<string, number>
}

export interface Threat {
  id: string
  type: string
  source_ip: string
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
  threat_score: number
  description: string
  timestamp: string
  status: string
  action_taken?: string
  classification?: "confirmed" | "lead"
  destination_ip?: string
  destination_host?: string
  destination_port?: number
  packet_count?: number
  evidence?: string[]
  attack_stage?: string
  stage_name?: string
  stage_number?: number
  technique_id?: string
  technique_name?: string
  category?: string
  mitre_mapping?: MitreMapping
}

export interface Packet {
  timestamp: string
  source_ip: string | null
  dest_ip: string | null
  protocol: string
  application_protocol?: string | null
  source_port?: number | null
  dest_port?: number | null
  size_bytes: number
  flags?: string[]
  dns_query?: string | null
  dns_query_type?: string | null
  observed_host?: string | null
  security_alerts?: string[]
}

export interface Notification {
  id: string
  type: string
  title: string
  message: string
  severity: string
  timestamp: string
  read: boolean
}

export interface ThreatActionResponse {
  success: boolean
  message: string
  threat_id: string
  action: string
  status: string
}

export interface ThreatHuntResponse {
  status: string
  packets_analyzed: number
  confirmed_findings: number
  suspicious_leads: number
  best_finding: Threat | null
  findings: Threat[]
  timestamp: string
}

export interface User {
  id: string
  email: string
  role: "admin" | "viewer"
}

export interface AdminDashboard {
  total_packets: number
  total_threats: number
  medium_threats: number
  high_alert_threats: number
  critical_threats: number
  low_threats?: number
  system_health: string
  uptime_percent: number
  packet_stats: PacketStatistics
  last_update: string
}

export interface TrafficConnectionsSummary {
  unique_sources: number
  unique_destinations: number
  unique_connections: number
  most_active: Array<{
    connection: string
    packets: number
    bytes: number
  }>
  timestamp: string
}

export interface AdminTrafficSummary {
  summary: TrafficStats
  connections: TrafficConnectionsSummary
  timestamp: string
}

export interface ProxyClient {
  source_ip: string
  ip?: string
  request_count: number
  bytes_transferred?: number
  last_seen?: string
  last_host?: string | null
  last_destination_ip?: string | null
  last_destination_port?: number | null
}

export interface ProxyStatus {
  enabled: boolean
  host: string
  port: number
  listening: boolean
  clients: ProxyClient[]
  timestamp: string
}

export interface BlockedSite {
  domain: string
  blocked_at?: string
  reason?: string
  threat_id?: string
  threat_type?: string
  severity?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
  destination_host?: string
  source_ip?: string
  description?: string
  evidence?: string[]
  is_demo?: boolean
}

export interface BlockedSitesResponse {
  status?: string
  mode?: string
  blocked_sites: BlockedSite[]
  count: number
  timestamp: string
}

export interface AdminSettings {
  capture_enabled: boolean
  anomaly_detection_enabled: boolean
  alert_level: string
  auto_block: boolean
  backup_enabled: boolean
  pps_threshold: number
  port_scan_threshold: number
}

export interface HealthCheckResponse {
  status: string
  services: Record<string, string>
  timestamp: string
}

class APIError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message)
    this.name = "APIError"
  }
}

async function handleResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const error = await response
      .json()
      .catch(() => ({ detail: "Unknown error" }))
    throw new APIError(response.status, error.detail || "API Error")
  }

  if (response.status === 204) {
    return undefined as T
  }

  return response.json()
}

function buildUrl(path: string, params?: Record<string, string | number | undefined>) {
  const searchParams = new URLSearchParams()

  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== "") {
        searchParams.append(key, String(value))
      }
    })
  }

  const query = searchParams.toString()
  return query ? `${path}?${query}` : path
}

async function apiRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
  let response: Response

  try {
    response = await fetch(path, {
      cache: "no-store",
      ...init,
      headers: {
        ...DEFAULT_HEADERS,
        ...(init.headers || {}),
      },
    })
  } catch (error) {
    throw new APIError(0, "Unable to reach the backend right now. Make sure capture mode is still running.")
  }

  return handleResponse<T>(response)
}

// ===== TRAFFIC ENDPOINTS =====

export async function getTrafficStats(): Promise<TrafficStats> {
  const data = await apiRequest<{ summary?: TrafficStats } & TrafficStats>("/api/traffic")
  return data.summary || data
}

export async function getTrafficByProtocol(): Promise<TrafficProtocolResponse> {
  return apiRequest<TrafficProtocolResponse>("/api/traffic/by-protocol")
}

export async function getTrafficByPort() {
  return apiRequest("/api/traffic/by-port")
}

export async function getTrafficByApplication() {
  return apiRequest("/api/traffic/by-application")
}

export async function getConnectionPatterns() {
  return apiRequest("/api/traffic/connections")
}

export async function getBandwidthPrediction() {
  return apiRequest("/api/traffic/bandwidth-prediction")
}

export async function getTrafficHistory(timeRange = "hour") {
  return apiRequest(buildUrl("/api/traffic/history", { time_range: timeRange }))
}

export async function getNetworkTopology(mode = "live"): Promise<NetworkTopologyResponse> {
  return apiRequest<NetworkTopologyResponse>(buildUrl("/api/traffic/topology", { mode }))
}

// ===== THREAT ENDPOINTS =====

export async function getThreats(
  status = "all",
  severity?: string,
  mode?: string,
): Promise<{ threats: Threat[]; mode?: string; live_available?: boolean }> {
  return apiRequest<{ threats: Threat[]; mode?: string; live_available?: boolean }>(
    buildUrl("/api/threats", { status, severity, mode }),
  )
}

export async function getThreatHunt(limit = 5): Promise<ThreatHuntResponse> {
  return apiRequest<ThreatHuntResponse>(
    buildUrl("/api/threats/hunt", { limit }),
  )
}

export async function analyzeThreatsFull() {
  return apiRequest("/api/threats/analyze", {
    method: "POST",
  })
}

export async function getThreatIntelligence(threatId: string) {
  return apiRequest(`/api/threats/${encodeURIComponent(threatId)}/intelligence`)
}

export async function respondToThreat(threatId: string, action: string): Promise<ThreatActionResponse> {
  return apiRequest<ThreatActionResponse>(
    buildUrl(`/api/threats/${encodeURIComponent(threatId)}/respond`, { action }),
    {
      method: "POST",
    },
  )
}

export async function unlockThreat(threatId: string): Promise<{
  success: boolean
  message: string
  threat_id: string
  domain?: string
  status: string
  verified_unblocked: boolean
}> {
  return apiRequest<{
    success: boolean
    message: string
    threat_id: string
    domain?: string
    status: string
    verified_unblocked: boolean
  }>(`/api/threats/${encodeURIComponent(threatId)}/unlock`, {
    method: "POST",
  })
}

// ===== PACKET ENDPOINTS =====

export async function getPackets(
  limit = 100,
  offset = 0,
  mode?: string,
): Promise<{ packets: Packet[]; mode?: string; live_available?: boolean; origin?: string }> {
  return apiRequest<{ packets: Packet[]; mode?: string; live_available?: boolean; origin?: string }>(
    buildUrl("/api/packets", { limit, offset, mode }),
  )
}

export async function filterPackets(filters: {
  source_ip?: string
  dest_ip?: string
  protocol?: string
  port?: number
}) {
  return apiRequest(buildUrl("/api/packets/filter", filters), {
    method: "POST",
  })
}

export async function analyzePackets() {
  return apiRequest("/api/packets/analyze", {
    method: "POST",
  })
}

export async function getPacketStatistics(): Promise<PacketStatistics> {
  return apiRequest<PacketStatistics>("/api/packets/statistics")
}

export async function startPacketCapture(
  count = 100,
  timeout = 10,
  interfaceName?: string,
): Promise<StartCaptureResponse> {
  return apiRequest<StartCaptureResponse>(
    buildUrl("/api/packets/capture/start", { count, timeout, interface: interfaceName }),
    {
      method: "POST",
    },
  )
}

export interface CaptureStatusResponse {
  is_capturing: boolean
  status: string
  status_code: "ACTIVE" | "OFF" | "STARTING" | "PERMISSION_REQUIRED" | "NPCAP_MISSING" | "NO_INTERFACE" | "ERROR"
  packets_captured: number
  total_bytes: number
  stored_packets: number
  active_interface?: {
    id?: string
    name?: string
    description?: string
    ips?: string[]
    mac?: string
  }
  npcap_installed: boolean
  is_admin: boolean
  error_message?: string | null
  timestamp: string
}

export interface CaptureEnvironmentResponse {
  npcap_installed: boolean
  npcap_status: string
  is_admin: boolean
  status_code: string
  message: string
  active_interface?: {
    id?: string
    name?: string
    description?: string
    ips?: string[]
    mac?: string
  }
  interfaces: Array<{
    id: string
    name: string
    description: string
    ips: string[]
    mac: string
    is_loopback: boolean
  }>
}

export async function getLiveCaptureStatus(): Promise<CaptureStatusResponse> {
  return apiRequest<CaptureStatusResponse>("/api/packets/capture/status")
}

export async function startLivePacketCapture(interfaceName?: string): Promise<{ success: boolean; status: string; message: string }> {
  return apiRequest(buildUrl("/api/packets/capture/start-live", { interface: interfaceName }), {
    method: "POST",
  })
}

export async function stopLivePacketCapture(): Promise<{ success: boolean; status: string; message: string }> {
  return apiRequest("/api/packets/capture/stop-live", {
    method: "POST",
  })
}

export async function getCaptureEnvironment(): Promise<CaptureEnvironmentResponse> {
  return apiRequest<CaptureEnvironmentResponse>("/api/packets/capture/environment")
}

export async function explainPacketPrediction(packet: any): Promise<PacketExplanationResponse> {
  return apiRequest<PacketExplanationResponse>("/api/packets/explain", {
    method: "POST",
    body: JSON.stringify(packet),
  })
}

// ===== ADMIN ENDPOINTS =====

export async function getAdminDashboard(): Promise<AdminDashboard> {
  return apiRequest<AdminDashboard>("/api/admin/dashboard")
}

export async function getAdminSettings(): Promise<AdminSettings> {
  return apiRequest<AdminSettings>("/api/admin/settings")
}

export async function updateAdminSettings(settings: {
  pps_threshold?: number
  port_scan_threshold?: number
  alert_level?: string
}) {
  return apiRequest(buildUrl("/api/admin/settings", settings), {
    method: "PUT",
  })
}

export async function getThreatsSummary() {
  return apiRequest("/api/admin/threats-summary")
}

export async function getThreatssSummary() {
  return getThreatsSummary()
}

export async function getTrafficSummary(): Promise<AdminTrafficSummary> {
  return apiRequest<AdminTrafficSummary>("/api/admin/traffic-summary")
}

export async function getProxyStatus(): Promise<ProxyStatus> {
  return apiRequest<ProxyStatus>("/api/admin/proxy-status")
}

export async function getBlockedSites(mode = "all"): Promise<BlockedSitesResponse> {
  return apiRequest<BlockedSitesResponse>(buildUrl("/api/admin/blocked-sites", { mode }))
}

export async function unblockSite(domain: string): Promise<{ success: boolean; message: string; domain: string }> {
  return apiRequest<{ success: boolean; message: string; domain: string }>(
    `/api/admin/blocked-sites/${encodeURIComponent(domain)}`,
    {
      method: "DELETE",
    },
  )
}

export async function clearBlockedSites(): Promise<{ success: boolean; message: string; cleared_domains: string[] }> {
  return apiRequest<{ success: boolean; message: string; cleared_domains: string[] }>("/api/admin/blocked-sites", {
    method: "DELETE",
  })
}

// ===== NOTIFICATIONS ENDPOINTS =====

export async function getNotifications(): Promise<{ notifications: Notification[] }> {
  return apiRequest<{ notifications: Notification[] }>("/api/notifications")
}

// ===== USERS ENDPOINTS =====

export async function getUsers(): Promise<{ users: User[] }> {
  return apiRequest<{ users: User[] }>("/api/users")
}

export async function createUser(userData: {
  email: string
  password?: string
  role: User["role"]
}): Promise<User> {
  return apiRequest<User>("/api/users", {
    method: "POST",
    body: JSON.stringify(userData),
  })
}

export async function deleteUser(userId: string) {
  return apiRequest(`/api/users/${encodeURIComponent(userId)}`, {
    method: "DELETE",
  })
}

// ===== HEALTH CHECK =====

export async function healthCheck(): Promise<HealthCheckResponse> {
  return apiRequest<HealthCheckResponse>("/health")
}

// ===== MITRE ATT&CK ENDPOINTS =====

export async function getMitreTaxonomy(): Promise<any> {
  return apiRequest<any>("/api/mitre/taxonomy")
}

export async function getMitreAttackChain(mode = "all"): Promise<AttackChainResponse> {
  return apiRequest<AttackChainResponse>(buildUrl("/api/mitre/attack-chain", { mode }))
}

export async function getMitreStages(mode = "all"): Promise<AttackChainResponse> {
  return apiRequest<AttackChainResponse>(buildUrl("/api/mitre/stages", { mode }))
}

export async function mapThreatToMitre(threatType: string): Promise<MitreMapping> {
  return apiRequest<MitreMapping>(
    buildUrl("/api/mitre/map-threat", { threat_type: threatType }),
    { method: "POST" }
  )
}

export async function scanWebsiteUrl(url: string, mode?: string): Promise<UrlScanResponse> {
  return apiRequest<UrlScanResponse>("/api/threats/scan-url", {
    method: "POST",
    body: JSON.stringify({ url, mode }),
  })
}

export async function simulateAttackScenario(scenarioType: "multi_stage" | "trojan" = "multi_stage"): Promise<{
  success: boolean
  scenario_type: string
  injected_count: number
  attack_chain: AttackChainResponse
}> {
  return apiRequest(buildUrl("/api/mitre/simulate-scenario", { scenario_type: scenarioType }), {
    method: "POST",
  })
}

export async function clearSimulation(): Promise<{
  success: boolean
  cleared_count: number
  attack_chain: AttackChainResponse
}> {
  return apiRequest("/api/mitre/clear-simulation", {
    method: "POST",
  })
}

// ===== ML BENCHMARK & PREDICTION ENDPOINTS =====

export async function getMLBenchmark(): Promise<any> {
  return apiRequest<any>("/api/ml/benchmark")
}

export async function trainMLBaseline(): Promise<any> {
  return apiRequest<any>("/api/ml/train-baseline", {
    method: "POST",
  })
}

export async function predictPacketML(packetData?: Partial<Packet>): Promise<MLPredictionResponse> {
  return apiRequest<MLPredictionResponse>("/api/ml/predict-packet", {
    method: "POST",
    body: packetData ? JSON.stringify(packetData) : undefined,
  })
}

// ===== REAL CIC-IDS2018 LSTM FORECASTING ENDPOINTS =====

export interface ForecastStep {
  step: number
  probability: number
}

export interface FeatureImportanceItem {
  feature: string
  importance: number
}

export interface AttackForecastResponse {
  status: string
  mode?: "live" | "simulation"
  origin?: string
  is_demo?: boolean
  collected_states?: number
  required_states?: number
  message?: string
  error?: string
  current_probability?: number | null
  forecast?: ForecastStep[]
  predicted_stage?: string
  predicted_stage_index?: number
  stage_confidence?: number
  top_features?: FeatureImportanceItem[]
  window_size?: number
  prediction_horizon?: number
}

export async function getAttackForecast(payload?: { window_sequence?: number[][]; packet_data?: any }): Promise<AttackForecastResponse> {
  return apiRequest<AttackForecastResponse>("/api/forecast", {
    method: "POST",
    body: payload ? JSON.stringify(payload) : JSON.stringify({}),
  })
}

export async function getForecastMetrics(): Promise<any> {
  return apiRequest<any>("/api/forecast/metrics")
}

export interface FileUploadAnalysisResponse {
  status: string
  filename: string
  file_type: string
  file_size_bytes: number
  flows_extracted: number
  window_states: number
  feature_dim: number
  forecast: {
    current_probability: number
    forecast: ForecastStep[]
    predicted_stage: string
    predicted_stage_index: number
    stage_confidence: number
    top_features: FeatureImportanceItem[]
    window_size: number
    prediction_horizon: number
  }
  timestamp: string
}

export async function uploadTrafficFile(file: File): Promise<FileUploadAnalysisResponse> {
  const formData = new FormData()
  formData.append("file", file)

  const response = await fetch("/api/forecast/upload", {
    method: "POST",
    body: formData,
  })

  if (!response.ok) {
    const errText = await response.text()
    try {
      const errJson = JSON.parse(errText)
      throw new Error(errJson.detail || errJson.message || "File upload processing failed.")
    } catch {
      throw new Error(errText || `Server error ${response.status}`)
    }
  }

  return response.json()
}

export async function processSampleDemoFile(sampleType = "pcap"): Promise<FileUploadAnalysisResponse & { is_demo?: boolean; origin?: string }> {
  return apiRequest<FileUploadAnalysisResponse & { is_demo?: boolean; origin?: string }>(
    buildUrl("/api/forecast/sample-demo", { sample_type: sampleType }),
    {
      method: "POST",
    }
  )
}


