"""
Consolidated API routes for the NetGuard backend.
Integrated with real services for packet capture, threat detection, and traffic analysis.
"""

from fastapi import APIRouter, HTTPException, Query, UploadFile, File
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
import os
import sys
import tempfile
import numpy as np
from app.services.packet_capture import PacketCaptureService
from app.services.mobile_proxy import MobileProxyService
from app.services.threat_detection import ThreatDetectionService
from app.services.traffic_analysis import TrafficAnalysisService
from app.services.mitre_mapping import MitreMappingService
from app.services.ml_benchmark import MLBenchmarkService
from app.services.forecast_service import ForecastService

# ===== Initialize Services =====
# These service instances hold the backend state that the route handlers expose
# to the frontend: packets, threats, proxy status, traffic summaries, MITRE mapping, ML benchmark, and LSTM Forecasting.
packet_service = PacketCaptureService()
threat_service = ThreatDetectionService()
proxy_service = MobileProxyService(packet_service, threat_service)
traffic_service = TrafficAnalysisService()
mitre_service = MitreMappingService()
ml_service = MLBenchmarkService()
forecast_service = ForecastService()

# ===== Request/Response Models =====
# These Pydantic models are local API-side shapes used for request/response typing
# inside this routes module.

class TrafficStats(BaseModel):
    timestamp: datetime
    packets_per_second: float
    bytes_per_second: float
    protocol: str

class ThreatData(BaseModel):
    id: str
    type: str
    source_ip: str
    severity: str
    timestamp: datetime
    status: str

class PacketData(BaseModel):
    id: str
    timestamp: datetime
    source_ip: str
    dest_ip: str
    protocol: str
    port: int
    size: int

class UserCreateRequest(BaseModel):
    email: str
    password: Optional[str] = None
    role: str

class UrlScanRequest(BaseModel):
    url: str
    mode: Optional[str] = "live"

# In-memory user store for the dashboard admin panel
users_store: List[Dict[str, str]] = [
    {"id": "user_1", "email": "admin@netguard.local", "role": "admin"},
    {"id": "user_2", "email": "viewer@netguard.local", "role": "viewer"},
]

# ===== TRAFFIC ROUTES =====
traffic_router = APIRouter(prefix="/api/traffic", tags=["Traffic Analysis"])

@traffic_router.get("")
async def get_traffic(time_range: str = Query("hour", description="Time range for analysis")):
    """Get network traffic statistics with real packet data"""
    try:
        # This endpoint is the traffic dashboard entry point: pull the current
        # packet snapshot first, then layer summaries on top of it.
        packets = packet_service.packets
        stats = await packet_service.get_packet_statistics()
        
        # Get traffic summary
        summary = await traffic_service.get_traffic_summary(packets, time_range)
        
        # Get protocol breakdown
        protocol_data = await traffic_service.analyze_by_protocol(packets)
        
        return {
            "status": "success",
            "summary": summary,
            "protocols": protocol_data.get("protocols", {}),
            "stats": stats
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Traffic analysis failed: {str(e)}")

@traffic_router.get("/by-protocol")
async def get_traffic_by_protocol():
    """Get detailed protocol breakdown"""
    try:
        packets = packet_service.packets
        protocol_data = await traffic_service.analyze_by_protocol(packets)
        return protocol_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@traffic_router.get("/by-port")
async def get_traffic_by_port():
    """Get traffic breakdown by port"""
    try:
        packets = packet_service.packets
        port_data = await traffic_service.analyze_by_port(packets)
        return port_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@traffic_router.get("/by-application")
async def get_traffic_by_application():
    """Get traffic breakdown by application type"""
    try:
        packets = packet_service.packets
        app_data = await traffic_service.analyze_by_application(packets)
        return app_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@traffic_router.get("/connections")
async def get_connection_patterns():
    """Get source-destination connection patterns"""
    try:
        packets = packet_service.packets
        connections = await traffic_service.analyze_connection_patterns(packets)
        return connections
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@traffic_router.get("/bandwidth-prediction")
async def predict_bandwidth():
    """Predict future bandwidth requirements"""
    try:
        packets = packet_service.packets
        prediction = await traffic_service.predict_bandwidth_requirements(packets)
        return prediction
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@traffic_router.get("/history")
async def get_traffic_history(time_range: str = "hour", interval: str = "minute"):
    """Get traffic history for charts (simulated based on current packets)"""
    try:
        packets = packet_service.packets
        stats = await packet_service.get_packet_statistics()
        
        # Generate historical data points (simplified)
        history_points = []
        if packets:
            chunk_size = max(1, len(packets) // 10)
            for i in range(0, len(packets), chunk_size):
                chunk = packets[i:i+chunk_size]
                history_points.append({
                    "timestamp": datetime.now().isoformat(),
                    "packets": len(chunk),
                    "bytes": sum(p.get("size_bytes", 0) for p in chunk)
                })
        
        return {
            "time_range": time_range,
            "interval": interval,
            "data": history_points if history_points else []
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@traffic_router.get("/topology")
async def get_network_topology(mode: str = Query("live", description="Mode: live or demo")):
    """Get network device connectivity and packet flow topology with Live vs Demo isolation."""
    try:
        packets = packet_service.packets
        topology = await traffic_service.get_network_topology(packets, mode=mode)
        return topology
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ===== THREATS ROUTES =====
threats_router = APIRouter(prefix="/api/threats", tags=["Threat Detection"])

@threats_router.get("")
async def get_threats(
    status: str = Query("active", description="Filter by status"),
    severity: Optional[str] = Query(None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    mode: str = Query("all", description="Mode: live, demo, or all")
):
    """Get detected threats with strict Live vs Demo mode separation."""
    try:
        packets = packet_service.packets
        stats = await packet_service.get_packet_statistics()
        
        # Run threat detection algorithm on live packets
        await threat_service.detect_threats(packets, stats)
        
        if mode == "live":
            # Live mode returns ONLY dynamically detected Npcap anomalies
            threat_list = threat_service.detected_threats
        elif mode == "demo":
            # Demo mode returns ONLY pre-seeded demonstration threats
            if not threat_service.manual_threats:
                threat_service.simulate_attack_scenario("multi_stage")
            threat_list = threat_service.manual_threats
        else:
            # Default / 'all' returns merged list
            if not threat_service.manual_threats and not threat_service.detected_threats:
                threat_service.simulate_attack_scenario("multi_stage")
            threat_list = threat_service.threats
        
        # Filter by parameters
        filtered_threats = threat_list
        if status and status.lower() != "all":
            filtered_threats = [t for t in filtered_threats if t.get("status") == status]
        if severity:
            filtered_threats = [t for t in filtered_threats if t.get("severity") == severity]
        
        # Enrich with MITRE ATT&CK mapping
        for t in filtered_threats:
            t["mitre_mapping"] = mitre_service.map_threat(t.get("type", ""), t)

        return {
            "status": "success",
            "mode": mode,
            "live_available": len(packets) > 0,
            "threat_count": len(filtered_threats),
            "threats": filtered_threats,
            "last_scan": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@threats_router.get("/hunt")
async def hunt_threats(limit: int = Query(5, ge=1, le=10, description="Maximum number of findings to return")):
    """Return the strongest confirmed threat or suspicious live lead from captured packets."""
    try:
        packets = packet_service.packets
        stats = await packet_service.get_packet_statistics()
        hunt_results = await threat_service.hunt_live_threats(packets, stats, limit=limit)

        if "best_finding" in hunt_results and hunt_results["best_finding"]:
            hunt_results["best_finding"]["mitre_mapping"] = mitre_service.map_threat(
                hunt_results["best_finding"].get("type", ""), hunt_results["best_finding"]
            )
        for f in hunt_results.get("findings", []):
            f["mitre_mapping"] = mitre_service.map_threat(f.get("type", ""), f)

        return {
            "status": "success",
            **hunt_results,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@threats_router.post("/{threat_id}/respond")
async def respond_to_threat(
    threat_id: str,
    action: str = Query(..., description="Action: BLOCK, ALERT, INVESTIGATE, IGNORE")
):
    """Take action on a threat"""
    try:
        result = await threat_service.respond_to_threat(threat_id, action)
        
        if result.get("success"):
            blocked_domain = result.get("blocked_domain")
            if action == "BLOCK" and blocked_domain:
                await proxy_service.drop_connections_for_domain(blocked_domain)
            return result
        raise HTTPException(status_code=404, detail=result.get("error"))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@threats_router.post("/{threat_id}/unlock")
async def unlock_threat_endpoint(threat_id: str):
    """Unlock a threat, remove active firewall/proxy block, and restore status to active."""
    try:
        result = threat_service.unlock_threat(threat_id)
        if result.get("success"):
            blocked_domain = result.get("domain")
            if blocked_domain:
                await proxy_service.drop_connections_for_domain(blocked_domain)
            return result
        raise HTTPException(status_code=404, detail=result.get("error"))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@threats_router.get("/{threat_id}/intelligence")
async def get_threat_intelligence(threat_id: str):
    """Get detailed threat intelligence"""
    try:
        intelligence = await threat_service.get_threat_intelligence(threat_id)
        
        if "error" in intelligence:
            raise HTTPException(status_code=404, detail=intelligence["error"])
        
        return intelligence
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@threats_router.post("/analyze")
async def analyze_for_threats():
    """Perform anomaly detection analysis on current traffic"""
    try:
        packets = packet_service.packets
        stats = await packet_service.get_packet_statistics()
        
        # Run threat detection
        threats = await threat_service.detect_threats(packets, stats)
        
        # Count by severity
        severity_breakdown = {
            "CRITICAL": len([t for t in threats if t.get("severity") == "CRITICAL"]),
            "HIGH": len([t for t in threats if t.get("severity") == "HIGH"]),
            "MEDIUM": len([t for t in threats if t.get("severity") == "MEDIUM"]),
            "LOW": len([t for t in threats if t.get("severity") == "LOW"]),
        }
        
        return {
            "analysis_complete": True,
            "total_threats_detected": len(threats),
            "severity_breakdown": severity_breakdown,
            "threats": threats,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@threats_router.post("/scan-url")
async def scan_url_threat_endpoint(request: UrlScanRequest):
    """Analyze website/URL with explicit Live vs Demo mode support."""
    try:
        if request.mode == "demo":
            # Safe deterministic demo scan fixture
            url_lower = request.url.lower()
            if "phish" in url_lower or "bank" in url_lower:
                threat_cat = "Credential Phishing Domain"
                severity = "HIGH"
                stage = "Stage 3: Initial Access [T1566.002]"
                score = 0.89
            elif "trojan" in url_lower or "payload" in url_lower or "malware" in url_lower:
                threat_cat = "Trojan Payload Host"
                severity = "CRITICAL"
                stage = "Stage 4: Execution [T1204.002]"
                score = 0.96
            else:
                threat_cat = "Clean Domain Sample"
                severity = "LOW"
                stage = "Stage 1: Reconnaissance"
                score = 0.12

            return {
                "status": "success",
                "mode": "demo",
                "is_demo": True,
                "origin": "DEMO SCAN RESULT",
                "url": request.url,
                "domain": request.url.replace("https://", "").replace("http://", "").split("/")[0],
                "threat_category": threat_cat,
                "severity": severity,
                "threat_score": score,
                "mitre_stage": stage,
                "evidence": ["Deterministic demo fixture result", f"Evaluated under DEMO MODE: {threat_cat}"],
                "timestamp": datetime.now().isoformat()
            }
        
        # Real Live Scan
        res = await threat_service.scan_url(request.url)
        res["mode"] = "live"
        res["is_demo"] = False
        res["origin"] = "LIVE SCAN RESULT"
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ===== PACKETS ROUTES =====
packets_router = APIRouter(prefix="/api/packets", tags=["Packet Capture"])

@packets_router.get("")
async def get_packets(limit: int = 100, offset: int = 0, mode: str = Query("live", description="Mode: live or demo")):
    """Get captured packets with explicit Live vs Demo mode separation."""
    try:
        if mode == "demo":
            # Deterministic sample packet stream
            demo_packets = [
                {"id": f"pkt_demo_{i}", "source_ip": "192.168.1.105", "dest_ip": "185.220.101.5", "protocol": "TCP", "dest_port": 443 if i % 2 == 0 else 80, "size_bytes": 128 + i * 15, "timestamp": datetime.now().isoformat(), "is_demo": True, "origin": "DEMO PACKET STREAM"}
                for i in range(1, 21)
            ]
            return {
                "status": "success",
                "mode": "demo",
                "is_demo": True,
                "origin": "DEMO PACKET STREAM",
                "packets": demo_packets,
                "total": len(demo_packets),
                "limit": limit,
                "offset": offset,
                "timestamp": datetime.now().isoformat()
            }

        # Live packet stream
        packets = packet_service.packets[offset:offset+limit]
        return {
            "status": "success",
            "mode": "live",
            "is_demo": False,
            "origin": "LIVE PACKET STREAM",
            "live_available": len(packets) > 0,
            "packets": packets,
            "total": len(packet_service.packets),
            "limit": limit,
            "offset": offset,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@packets_router.get("/interfaces")
async def get_capture_interfaces():
    """Return available capture interfaces and the current default."""
    try:
        return packet_service.get_available_interfaces()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@packets_router.post("/explain")
async def explain_packet(packet: Dict[str, Any]):
    """
    Explain network characteristics contributing to infiltration prediction
    for an individual packet or flow using the 27-feature PyTorch LSTM model.
    """
    try:
        explanation = forecast_service.explain_packet_prediction(packet)
        return explanation
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Explainability evaluation failed: {str(e)}")

@packets_router.post("/filter")
async def filter_packets(
    source_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    port: Optional[int] = None
):
    """Filter packets by criteria"""
    try:
        filters = {}
        if source_ip:
            filters["source_ip"] = source_ip
        if dest_ip:
            filters["dest_ip"] = dest_ip
        if protocol:
            filters["protocol"] = protocol
        if port:
            filters["port"] = port
        
        filtered = await packet_service.filter_packets(**filters)
        
        return {
            "filters": filters,
            "count": len(filtered),
            "packets": filtered,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@packets_router.post("/analyze")
async def analyze_packet():
    """Deep packet inspection and analysis"""
    try:
        packets = packet_service.packets
        
        if not packets:
            return {"error": "No packets to analyze"}
        
        # Analyze patterns
        anomalies = []
        
        # Check for unusual packet sizes
        sizes = [p.get("size_bytes", 0) for p in packets if p.get("size_bytes")]
        if sizes:
            avg_size = sum(sizes) / len(sizes)
            large_packets = [p for p in packets if p.get("size_bytes", 0) > avg_size * 2]
            if large_packets:
                anomalies.append({
                    "type": "LARGE_PACKETS",
                    "count": len(large_packets),
                    "threshold": avg_size * 2
                })
        
        ml_score = round(min(1.0, len(anomalies) * 0.35 + (0.1 if packets else 0.0)), 4)
        
        return {
            "total_packets_analyzed": len(packets),
            "anomalies_found": len(anomalies),
            "anomaly_details": anomalies,
            "ml_score": ml_score,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@packets_router.get("/capture/status")
async def get_live_capture_status():
    """Return real-time packet capture status, active interface, and packet metrics."""
    try:
        return packet_service.get_capture_status()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@packets_router.post("/capture/start-live")
async def start_live_capture(
    interface: Optional[str] = Query(None, description="Network interface to capture from")
):
    """Start continuous live background packet capture on the active interface."""
    try:
        result = packet_service.start_background_capture(interface=interface)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@packets_router.post("/capture/stop-live")
async def stop_live_capture():
    """Stop continuous live background packet capture."""
    try:
        result = packet_service.stop_background_capture()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@packets_router.get("/capture/environment")
async def get_capture_environment():
    """Return environment diagnostic details including Npcap status, elevation, and interfaces."""
    try:
        return packet_service.check_environment()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@packets_router.post("/capture/start")
async def start_capture(
    interface: Optional[str] = Query(None, description="Network interface to capture from"),
    count: int = Query(100, description="Number of packets to capture"),
    timeout: int = Query(10, description="Timeout in seconds")
):
    """Start packet capture"""
    try:
        # Capture prefers an explicit interface, then an env override, then the
        # backend's best guess for the active interface.
        capture_interface = (
            interface
            or os.getenv("CAPTURE_INTERFACE")
            or packet_service.get_preferred_interface()
        )
        packets = await packet_service.capture_packets(
            interface=capture_interface,
            count=count,
            timeout=timeout
        )
        
        if isinstance(packets, dict) and "error" in packets:
            raise HTTPException(status_code=500, detail=packets["error"])
        
        return {
            "capture_id": f"cap_{datetime.now().timestamp()}",
            "status": "started",
            "interface": capture_interface or "default",
            "packets_captured": len(packets) if isinstance(packets, list) else 0,
            "count": count,
            "timeout": timeout,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@packets_router.post("/capture/stop")
async def stop_capture():
    """Stop packet capture and get statistics"""
    try:
        stats = await packet_service.get_packet_statistics()
        
        return {
            "success": True,
            "packets_captured": stats.get("total_packets", 0),
            "total_bytes": stats.get("total_bytes", 0),
            "statistics": stats,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@packets_router.get("/statistics")
async def get_packet_statistics():
    """Get packet capture statistics"""
    try:
        stats = await packet_service.get_packet_statistics()
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ===== ADMIN ROUTES =====
admin_router = APIRouter(prefix="/api/admin", tags=["Admin"])

@admin_router.get("/proxy-status")
async def get_proxy_status():
    """Return local proxy status for mobile testing."""
    # The frontend uses this to drive the Observed Devices card and the
    # proxy online/offline badge.
    proxy_port = int(os.getenv("PROXY_PORT", "8888"))
    return {
        "enabled": os.getenv("PROXY_ENABLED", "0").lower() in {"1", "true", "yes", "on"},
        "host": os.getenv("PROXY_HOST", "0.0.0.0"),
        "port": proxy_port,
        "listening": proxy_service.server is not None,
        "clients": proxy_service.get_active_clients(),
        "timestamp": datetime.now().isoformat(),
    }

@admin_router.get("/blocked-sites")
async def get_blocked_sites(mode: str = Query("all", description="Mode: all, live, or demo")):
    """Return domains currently blocked by proxy response actions with Live vs Demo isolation."""
    sites = threat_service.get_blocked_domains(mode=mode)
    return {
        "status": "success",
        "mode": mode,
        "blocked_sites": sites,
        "count": len(sites),
        "timestamp": datetime.now().isoformat(),
    }

@admin_router.delete("/blocked-sites")
async def clear_blocked_sites():
    """Clear every blocked website rule from the proxy."""
    return threat_service.clear_blocked_domains()

@admin_router.delete("/blocked-sites/{domain}")
async def unblock_site(domain: str):
    """Remove a single blocked website rule from the proxy."""
    result = threat_service.unblock_domain(domain)
    if result.get("success"):
        return result
    raise HTTPException(status_code=404, detail=result.get("error"))

@admin_router.get("/dashboard")
async def admin_dashboard():
    """Admin dashboard overview"""
    try:
        # This is the high-level overview API used by the dashboard cards.
        # It intentionally counts low-severity threats separately.
        packets = packet_service.packets
        stats = await packet_service.get_packet_statistics()
        threats = await threat_service.detect_threats(packets, stats) if packets else []

        visible_threats = [t for t in threats if t.get("severity") != "LOW"]
        medium_threats = len([t for t in visible_threats if t.get("severity") == "MEDIUM"])
        high_alert_threats = len(
            [t for t in visible_threats if t.get("severity") in {"HIGH", "CRITICAL"}]
        )
        critical_threats = len([t for t in threats if t.get("severity") == "CRITICAL"])

        if critical_threats > 0:
            system_health = "WARNING"
        elif high_alert_threats > 0:
            system_health = "ELEVATED"
        elif medium_threats > 0:
            system_health = "MONITORING"
        else:
            system_health = "HEALTHY"

        uptime = 100.0 if system_health == "HEALTHY" else (95.0 if system_health == "MONITORING" else 85.0)

        return {
            "total_packets": stats.get("total_packets", 0),
            "total_threats": len(visible_threats),
            "medium_threats": medium_threats,
            "high_alert_threats": high_alert_threats,
            "critical_threats": critical_threats,
            "low_threats": len([t for t in threats if t.get("severity") == "LOW"]),
            "system_health": system_health,
            "uptime_percent": uptime,
            "packet_stats": stats,
            "last_update": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@admin_router.get("/settings")
async def get_settings():
    """Get system settings"""
    return {
        "capture_enabled": True,
        "anomaly_detection_enabled": True,
        "alert_level": "MEDIUM",
        "auto_block": False,
        "backup_enabled": True,
        "pps_threshold": threat_service.pps_threshold,
        "port_scan_threshold": threat_service.port_scan_threshold
    }

@admin_router.put("/settings")
async def update_settings(
    pps_threshold: Optional[int] = None,
    port_scan_threshold: Optional[int] = None,
    alert_level: Optional[str] = None
):
    """Update system settings"""
    try:
        if pps_threshold:
            threat_service.pps_threshold = pps_threshold
        if port_scan_threshold:
            threat_service.port_scan_threshold = port_scan_threshold
        
        return {
            "success": True,
            "message": "Settings updated",
            "pps_threshold": threat_service.pps_threshold,
            "port_scan_threshold": threat_service.port_scan_threshold,
            "alert_level": alert_level
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@admin_router.get("/threats-summary")
async def get_threats_summary():
    """Get threat summary for admin"""
    try:
        packets = packet_service.packets
        stats = await packet_service.get_packet_statistics()
        threats = await threat_service.detect_threats(packets, stats) if packets else []
        
        threat_types = {}
        for threat in threats:
            threat_type = threat.get("type", "Unknown")
            threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
        
        return {
            "total_threats": len(threats),
            "threat_types": threat_types,
            "threats": threats,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@admin_router.get("/traffic-summary")
async def get_traffic_summary():
    """Get traffic summary for admin"""
    try:
        packets = packet_service.packets
        summary = await traffic_service.get_traffic_summary(packets)
        connections = await traffic_service.analyze_connection_patterns(packets)
        
        return {
            "summary": summary,
            "connections": connections,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ===== HEALTH CHECK =====
health_router = APIRouter(tags=["Health"])

@health_router.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "services": {
            "packet_capture": "operational",
            "threat_detection": "operational",
            "traffic_analysis": "operational"
        },
        "timestamp": datetime.now().isoformat()
    }

# ===== NOTIFICATIONS ROUTER =====
notifications_router = APIRouter(prefix="/api/notifications", tags=["Notifications"])

@notifications_router.get("")
async def get_notifications():
    """Get recent notifications"""
    # Notifications are a mix of stored response-action events and live threat
    # notifications generated from the current threat snapshot.
    packets = packet_service.packets
    stats = await packet_service.get_packet_statistics()
    threats = await threat_service.detect_threats(packets, stats)
    notifications = threat_service.get_notifications(threats)
    
    return {
        "notifications": notifications,
        "total": len(notifications)
    }

# ===== USERS ROUTES =====
users_router = APIRouter(prefix="/api/users", tags=["Users"])

@users_router.get("")
async def get_users():
    """Get list of users"""
    return {"users": users_store}

@users_router.post("")
async def create_user(user: UserCreateRequest):
    """Create new user"""
    role = user.role.lower()

    if role not in ["admin", "viewer"]:
        raise HTTPException(status_code=400, detail="Invalid role")

    if any(existing_user["email"].lower() == user.email.lower() for existing_user in users_store):
        raise HTTPException(status_code=409, detail="User already exists")

    new_user = {
        "id": f"user_{len(users_store) + 1}",
        "email": user.email,
        "role": role
    }
    users_store.append(new_user)

    return new_user

@users_router.delete("/{user_id}")
async def delete_user(user_id: str):
    """Delete user"""
    for index, existing_user in enumerate(users_store):
        if existing_user["id"] == user_id:
            deleted_user = users_store.pop(index)
            return {
                "success": True,
                "message": f"User {user_id} deleted",
                "user": deleted_user
            }

    raise HTTPException(status_code=404, detail="User not found")

@notifications_router.post("/{notif_id}/read")
async def mark_notification_read(notif_id: str):
    """Mark notification as read"""
    return {
        "success": True,
        "notification_id": notif_id
    }

@notifications_router.delete("/{notif_id}")
async def delete_notification(notif_id: str):
    """Delete notification"""
    return {"success": True, "notification_id": notif_id}


# ===== MITRE ATT&CK ROUTES =====
mitre_router = APIRouter(prefix="/api/mitre", tags=["MITRE ATT&CK Mapping"])

@mitre_router.get("/taxonomy")
async def get_mitre_taxonomy():
    """Get the full MITRE ATT&CK taxonomy and tactics matrix"""
    return mitre_service.get_taxonomy()

@mitre_router.get("/attack-chain")
async def get_mitre_attack_chain(mode: str = Query("all", description="Mode: all, live, or demo")):
    """Get active attack kill-chain progression with Live vs Demo isolation."""
    packets = packet_service.packets
    stats = await packet_service.get_packet_statistics()
    await threat_service.detect_threats(packets, stats)

    if mode == "live":
        threat_list = threat_service.detected_threats
    elif mode == "demo":
        if not threat_service.manual_threats:
            threat_service.simulate_attack_scenario("multi_stage")
        threat_list = threat_service.manual_threats
    else:
        if not threat_service.manual_threats and not threat_service.detected_threats:
            threat_service.simulate_attack_scenario("multi_stage")
        threat_list = threat_service.threats

    summary = mitre_service.build_attack_chain_summary(threat_list)
    summary["mode"] = mode
    summary["is_demo"] = (mode == "demo")
    return summary

@mitre_router.post("/map-threat")
async def map_threat_endpoint(threat_type: str = Query(..., description="Threat type identifier")):
    """Map any threat type to MITRE tactic and technique"""
    return mitre_service.map_threat(threat_type)

@mitre_router.post("/scan-url")
async def mitre_scan_url_endpoint(request: UrlScanRequest):
    """Scan URL and return MITRE ATT&CK Stage classification, danger level, and safety warning"""
    try:
        return await threat_service.scan_url(request.url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@mitre_router.get("/stages")
async def get_mitre_stages(mode: str = Query("all", description="Mode: all, live, or demo")):
    """Get all 14 MITRE ATT&CK kill-chain stages with active threat counts and progression with Live vs Demo isolation."""
    packets = packet_service.packets
    stats = await packet_service.get_packet_statistics()
    await threat_service.detect_threats(packets, stats)

    if mode == "live":
        threat_list = threat_service.detected_threats
    elif mode == "demo":
        if not threat_service.manual_threats:
            threat_service.simulate_attack_scenario("multi_stage")
        threat_list = threat_service.manual_threats
    else:
        if not threat_service.manual_threats and not threat_service.detected_threats:
            threat_service.simulate_attack_scenario("multi_stage")
        threat_list = threat_service.threats

    summary = mitre_service.build_attack_chain_summary(threat_list)
    summary["mode"] = mode
    summary["is_demo"] = (mode == "demo")
    return summary

@mitre_router.post("/simulate-scenario")
async def simulate_attack_scenario_endpoint(scenario_type: str = Query("multi_stage", description="Scenario: multi_stage or trojan")):
    """Inject simulated realistic multi-stage threats to light up the MITRE Matrix"""
    simulated = threat_service.simulate_attack_scenario(scenario_type)
    packets = packet_service.packets
    stats = await packet_service.get_packet_statistics()
    threats = await threat_service.detect_threats(packets, stats)
    summary = mitre_service.build_attack_chain_summary(threats)
    return {
        "success": True,
        "scenario_type": scenario_type,
        "injected_count": len(simulated),
        "attack_chain": summary
    }

@mitre_router.post("/clear-simulation")
async def clear_simulation_endpoint():
    """Clear all simulated threats"""
    cleared = threat_service.clear_simulated_threats()
    packets = packet_service.packets
    stats = await packet_service.get_packet_statistics()
    threats = await threat_service.detect_threats(packets, stats)
    summary = mitre_service.build_attack_chain_summary(threats)
    return {
        "success": True,
        "cleared_count": cleared,
        "attack_chain": summary
    }


# ===== ML BENCHMARK & LOGISTIC REGRESSION BASELINE ROUTES =====
ml_router = APIRouter(prefix="/api/ml", tags=["ML Baseline & Benchmark"])

@ml_router.get("/benchmark")
async def get_ml_benchmark():
    """Get fair benchmark metrics: F1, Precision, Recall, False Positive Rate (FPR), ROC-AUC, Latency, Confusion Matrix"""
    return ml_service.get_benchmark()

@ml_router.post("/train-baseline")
async def train_baseline_model():
    """Retrain Logistic Regression baseline and AI model incorporating live captured packets"""
    packets = packet_service.packets
    result = ml_service.train_on_live_data(packets)
    return result

@ml_router.post("/predict-packet")
async def predict_packet_endpoint(packet_data: Optional[Dict[str, Any]] = None):
    """Run real-time inference on a packet using both Logistic Regression and AI Ensemble"""
    if not packet_data:
        if packet_service.packets:
            packet_data = packet_service.packets[-1]
        else:
            packet_data = {"size_bytes": 1024, "dest_port": 443, "protocol": "TCP", "flags": ["ACK"]}
    
    return ml_service.predict_packet(packet_data)


# ===== REAL CIC-IDS2018 LSTM TEMPORAL FORECASTING ROUTES =====
forecast_router = APIRouter(prefix="/api/forecast", tags=["Attack Forecasting"])

class ForecastRequest(BaseModel):
    window_sequence: Optional[List[List[float]]] = None
    packet_data: Optional[Dict[str, Any]] = None
    mode: Optional[str] = "live"

@forecast_router.post("")
async def get_attack_forecast(request: Optional[ForecastRequest] = None):
    """
    Generate real-time multi-step attack forecast using PyTorch LSTM World Model.
    Supports Live vs Demo mode with explicit live-availability checks.
    """
    mode = request.mode if request and request.mode else "live"
    
    if mode == "demo":
        # Deterministic simulation forecast
        return {
            "status": "success",
            "mode": "demo",
            "is_demo": True,
            "origin": "DEMO FORECAST SCENARIO",
            "live_available": False,
            "current_attack_probability": 0.84,
            "predicted_attack_stage": "Stage 12: Command and Control [T1071.001]",
            "risk_level": "HIGH",
            "forecast_horizon": [
                {"step": "+1s", "probability": 0.86, "stage": "Command & Control"},
                {"step": "+2s", "probability": 0.89, "stage": "Command & Control"},
                {"step": "+3s", "probability": 0.93, "stage": "Data Exfiltration"},
                {"step": "+4s", "probability": 0.95, "stage": "Data Exfiltration"},
                {"step": "+5s", "probability": 0.98, "stage": "Impact"}
            ],
            "top_feature_attributions": [
                {"feature": "flow_byts_s", "weight": 0.38, "description": "Abnormal outbound transfer rate"},
                {"feature": "syn_flag_cnt", "weight": 0.29, "description": "High SYN packet velocity"},
                {"feature": "flow_iat_mean", "weight": 0.18, "description": "Periodic beaconing cadence"}
            ],
            "timestamp": datetime.now().isoformat()
        }

    # Live Mode
    packets = packet_service.packets
    custom_window = request.window_sequence if request else None
    
    if request and request.packet_data:
        forecast_service.add_packet_features(request.packet_data)
        
    result = forecast_service.get_forecast(packets=packets, custom_window=custom_window)
    live_has_data = len(packets) > 0 or (custom_window is not None and len(custom_window) > 0)
    
    return {
        "status": "success",
        "mode": "live",
        "is_demo": False,
        "origin": "LIVE FORECAST",
        "live_available": live_has_data,
        "message": "Live traffic model evaluation active" if live_has_data else "LIVE DATA UNAVAILABLE - START CAPTURE MODE",
        **result
    }

@forecast_router.get("/metrics")
async def get_forecast_metrics():
    """Returns LSTM World Model vs Logistic Regression baseline benchmark metrics."""
    import json
    candidate_paths = [
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), "models", "trained", "benchmark_metrics.json"),
        os.path.join(getattr(sys, "_MEIPASS", ""), "models", "trained", "benchmark_metrics.json"),
        os.path.join(os.path.dirname(sys.executable), "models", "trained", "benchmark_metrics.json"),
        os.path.join(os.path.dirname(os.path.dirname(sys.executable)), "models", "trained", "benchmark_metrics.json"),
        os.path.abspath("models/trained/benchmark_metrics.json"),
    ]
    for path in candidate_paths:
        if path and os.path.exists(path):
            with open(path, "r") as f:
                return json.load(f)
    raise HTTPException(status_code=404, detail="Benchmark metrics not found. Run scripts/train_world_model.py first.")


@forecast_router.post("/upload")
async def upload_offline_traffic_file(file: UploadFile = File(...)):
    """
    Ingest offline PCAP (.pcap, .pcapng) or CSV network traffic file.
    Parses file, extracts 27-dimensional flow feature vectors, forms a 30-state temporal window,
    and runs PyTorch LSTM World Model inference to produce:
    - Current attack probability score
    - 5-step forward forecast timeline
    - Predicted MITRE ATT&CK stage
    - Feature attributions (explainability)
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required.")

    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in {".pcap", ".pcapng", ".csv"}:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file extension '{ext}'. Only .pcap, .pcapng, and .csv files are supported."
        )

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    tmp_path = ""
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        canonical_cols = [
            'flow_duration', 'tot_fwd_pkts', 'tot_bwd_pkts', 'totlen_fwd_pkts', 'totlen_bwd_pkts',
            'fwd_pkt_len_max', 'fwd_pkt_len_mean', 'bwd_pkt_len_max', 'bwd_pkt_len_mean',
            'flow_byts_s', 'flow_pkts_s', 'flow_iat_mean', 'flow_iat_std', 'fwd_iat_mean',
            'bwd_iat_mean', 'syn_flag_cnt', 'ack_flag_cnt', 'rst_flag_cnt', 'fin_flag_cnt',
            'psh_flag_cnt', 'pkt_len_mean', 'pkt_len_std', 'down_up_ratio', 'protocol_tcp',
            'protocol_udp', 'is_high_risk_port', 'fwd_bwd_bytes_ratio'
        ]

        features_list = []

        if ext in {".pcap", ".pcapng"}:
            from scripts.pcap_to_flow import extract_flows_from_pcap
            df = extract_flows_from_pcap(tmp_path)
            if df is None or df.empty:
                raise HTTPException(status_code=400, detail="Failed to extract network flows from PCAP file.")

            for col in canonical_cols:
                if col not in df.columns:
                    df[col] = 0.0

            features_list = df[canonical_cols].fillna(0.0).values.tolist()

        elif ext == ".csv":
            import pandas as pd
            from app.utils.csv_mapper import map_dataframe_to_27_canonical
            df_raw = pd.read_csv(tmp_path)
            if df_raw.empty:
                raise HTTPException(status_code=400, detail="CSV file is empty.")

            df = map_dataframe_to_27_canonical(df_raw)
            features_list = df.values.tolist()


        arr = np.array(features_list, dtype=np.float32)
        if len(arr) < 30:
            pad = np.tile(arr[-1:], (30 - len(arr), 1)) if len(arr) > 0 else np.zeros((30, 27), dtype=np.float32)
            window = np.vstack([arr, pad])
        else:
            window = arr[-30:]

        forecast_res = forecast_service.engine.forecast(window)

        return {
            "status": "success",
            "mode": "user_input",
            "is_demo": False,
            "origin": "USER FILE ANALYSIS",
            "filename": file.filename,
            "file_type": ext[1:].upper(),
            "file_size_bytes": len(content),
            "flows_extracted": len(features_list),
            "window_states": 30,
            "feature_dim": 27,
            "forecast": forecast_res,
            "timestamp": datetime.now().isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing file '{file.filename}': {str(e)}")
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass


@forecast_router.post("/sample-demo")
async def analyze_sample_demo_file(sample_type: str = Query("pcap", description="Sample type: pcap or csv")):
    """
    Process pre-loaded sample network capture (PCAP or CSV) under DEMO MODE for instant demonstration.
    """
    try:
        sample_name = "sample_exploit_traffic.pcap" if sample_type == "pcap" else "sample_network_flows.csv"
        # Generate 30 state sample window
        sample_window = np.zeros((30, 27), dtype=np.float32)
        sample_window[:, 0] = 120.0  # flow duration
        sample_window[:, 9] = 154000.0  # flow bytes/s
        sample_window[:, 15] = 45.0  # syn flag cnt

        forecast_res = forecast_service.engine.forecast(sample_window)

        return {
            "status": "success",
            "mode": "demo",
            "is_demo": True,
            "origin": "DEMO SAMPLE ANALYSIS",
            "filename": sample_name,
            "file_type": sample_type.upper(),
            "file_size_bytes": 184320 if sample_type == "pcap" else 42150,
            "flows_extracted": 142,
            "window_states": 30,
            "feature_dim": 27,
            "forecast": forecast_res,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing sample file: {str(e)}")



