"""
Lightweight HTTP/HTTPS proxy for mobile testing.
Routes phone traffic through the local backend so watched-site alerts can fire
from real mobile browsing without packet capture needing to sniff the router.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Optional, Tuple
from urllib.parse import urlsplit

from app.services.packet_capture import PacketCaptureService
from app.services.threat_detection import ThreatDetectionService
from app.services.mitre_mapping import MitreMappingService


class MobileProxyService:
    def __init__(self, packet_service: PacketCaptureService, threat_service: ThreatDetectionService):
        self.packet_service = packet_service
        self.threat_service = threat_service
        self.server: Optional[asyncio.base_events.Server] = None
        self.host = "0.0.0.0"
        self.port = 8888
        self.client_activity: dict[str, dict[str, Optional[str] | int]] = {}
        self.active_connections: list[dict[str, object]] = []

    async def start(self, host: str = "0.0.0.0", port: int = 8888) -> None:
        if self.server is not None:
            return

        self.host = host
        self.port = port
        self.server = await asyncio.start_server(self._handle_client, host, port)

    async def stop(self) -> None:
        if self.server is None:
            return

        self.server.close()
        await self.server.wait_closed()
        self.server = None

    async def _handle_client(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        # Every mobile request comes through this entry point first. From here we
        # split normal HTTP requests and HTTPS CONNECT tunnels into separate flows.
        peer = client_writer.get_extra_info("peername")
        source_ip = peer[0] if isinstance(peer, tuple) and peer else None

        try:
            request_head = await client_reader.readuntil(b"\r\n\r\n")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            client_writer.close()
            await client_writer.wait_closed()
            return

        try:
            method, target, version, headers = self._parse_request_head(request_head)

            if method.upper() == "CONNECT":
                await self._handle_connect(
                    client_reader,
                    client_writer,
                    request_head,
                    source_ip,
                    target,
                )
                return

            await self._handle_http(
                client_reader,
                client_writer,
                request_head,
                source_ip,
                method,
                target,
                version,
                headers,
            )
        except ValueError:
            await self._send_error(client_writer, 400, "Bad Request")
        except Exception:
            try:
                await self._send_error(client_writer, 502, "Bad Gateway")
            except Exception:
                try:
                    client_writer.close()
                    await client_writer.wait_closed()
                except Exception:
                    pass

    async def _handle_connect(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        request_head: bytes,
        source_ip: Optional[str],
        target: str,
    ) -> None:
        # CONNECT is the HTTPS path. We can still see the destination host, but
        # after the tunnel is open the payload stays encrypted end-to-end.
        destination_host, destination_port = self._parse_connect_target(target)
        if not destination_host:
            await self._send_error(client_writer, 400, "Invalid CONNECT target")
            return

        observation = self.packet_service.record_proxy_observation(
            source_ip=source_ip,
            destination_host=destination_host,
            destination_port=destination_port,
            request_bytes=len(request_head),
            application_protocol="HTTPS_TUNNEL",
        )
        self._record_client_activity(
            source_ip,
            destination_host,
            destination_port,
            observation.get("dest_ip"),
        )

        if self.threat_service.is_domain_blocked(destination_host):
            await self._send_blocked_response(client_writer, destination_host)
            return

        try:
            remote_reader, remote_writer = await asyncio.open_connection(destination_host, destination_port)
        except OSError:
            await self._send_error(client_writer, 502, "Bad Gateway")
            return

        client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await client_writer.drain()

        connection_entry = self._register_active_connection(destination_host, client_writer, remote_writer)
        try:
            await self._relay_bidirectional(client_reader, client_writer, remote_reader, remote_writer)
        finally:
            self._unregister_active_connection(connection_entry)

    async def _handle_http(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        request_head: bytes,
        source_ip: Optional[str],
        method: str,
        target: str,
        version: str,
        headers: dict[str, str],
    ) -> None:
        # Plain HTTP gives us the host and path directly, so this branch is where
        # we can log the request, answer connectivity probes, and enforce blocks early.
        destination_host, destination_port, request_path = self._parse_http_target(target, headers)
        if not destination_host:
            await self._send_error(client_writer, 400, "Missing Host header")
            return

        observation = self.packet_service.record_proxy_observation(
            source_ip=source_ip,
            destination_host=destination_host,
            destination_port=destination_port,
            request_bytes=len(request_head),
            application_protocol="HTTP_PROXY_HTTP",
        )
        self._record_client_activity(
            source_ip,
            destination_host,
            destination_port,
            observation.get("dest_ip"),
        )

        if await self._handle_connectivity_probe(client_writer, destination_host, request_path):
            return

        if self.threat_service.is_domain_blocked(destination_host):
            await self._send_blocked_response(client_writer, destination_host)
            return

        try:
            remote_reader, remote_writer = await asyncio.open_connection(destination_host, destination_port)
        except OSError:
            await self._send_error(client_writer, 502, "Bad Gateway")
            return

        rebuilt_request = self._rebuild_http_request(method, request_path, version, headers)
        remote_writer.write(rebuilt_request)
        await remote_writer.drain()

        connection_entry = self._register_active_connection(destination_host, client_writer, remote_writer)
        try:
            await self._relay_bidirectional(client_reader, client_writer, remote_reader, remote_writer)
        finally:
            self._unregister_active_connection(connection_entry)

    async def _relay_bidirectional(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        remote_reader: asyncio.StreamReader,
        remote_writer: asyncio.StreamWriter,
    ) -> None:
        async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                while True:
                    chunk = await reader.read(65536)
                    if not chunk:
                        break
                    writer.write(chunk)
                    await writer.drain()
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        await asyncio.gather(
            pipe(client_reader, remote_writer),
            pipe(remote_reader, client_writer),
            return_exceptions=True,
        )

    @staticmethod
    def _parse_request_head(request_head: bytes) -> Tuple[str, str, str, dict[str, str]]:
        text = request_head.decode("iso-8859-1", errors="ignore")
        lines = text.split("\r\n")
        if not lines or len(lines[0].split(" ")) < 3:
            raise ValueError("Invalid request line")

        method, target, version = lines[0].split(" ", 2)
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
        return method, target, version, headers

    @staticmethod
    def _parse_connect_target(target: str) -> Tuple[Optional[str], int]:
        host, port = MobileProxyService._split_host_and_port(target, default_port=443)
        return host, port

    @staticmethod
    def _parse_http_target(target: str, headers: dict[str, str]) -> Tuple[Optional[str], int, str]:
        if target.startswith("http://") or target.startswith("https://"):
            parsed = urlsplit(target)
            if not parsed.hostname:
                return None, 80, "/"
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
            return parsed.hostname, port, path

        if not target.startswith("/"):
            parsed = urlsplit(f"http://{target}")
            if parsed.hostname:
                port = parsed.port or 80
                path = parsed.path or "/"
                if parsed.query:
                    path = f"{path}?{parsed.query}"
                return parsed.hostname, port, path

        host_header = headers.get("host", "")
        host, port = MobileProxyService._split_host_and_port(host_header, default_port=80)
        if not host:
            return None, 80, target or "/"
        return host, port, target or "/"

    @staticmethod
    def _split_host_and_port(value: str, default_port: int) -> Tuple[Optional[str], int]:
        raw_value = value.strip()
        if not raw_value:
            return None, default_port

        if raw_value.startswith("["):
            end_index = raw_value.find("]")
            if end_index == -1:
                return raw_value.strip("[]"), default_port
            host = raw_value[1:end_index]
            remainder = raw_value[end_index + 1:]
            if remainder.startswith(":") and remainder[1:].isdigit():
                return host, int(remainder[1:])
            return host, default_port

        if raw_value.count(":") == 1:
            host, port = raw_value.split(":", 1)
            if port.isdigit():
                return host.strip(), int(port)

        if raw_value.count(":") > 1:
            host, separator, port = raw_value.rpartition(":")
            if separator and port.isdigit():
                return host.strip("[] "), int(port)

        return raw_value.strip("[] "), default_port

    def get_active_clients(self, recent_seconds: int = 15) -> list[dict[str, Optional[str] | int]]:
        cutoff = datetime.now() - timedelta(seconds=recent_seconds)
        active_clients = []

        for source_ip, profile in self.client_activity.items():
            last_seen = profile.get("last_seen")
            if not last_seen:
                continue

            try:
                last_seen_dt = datetime.fromisoformat(str(last_seen))
            except ValueError:
                continue

            if last_seen_dt < cutoff:
                continue

            active_clients.append(
                {
                    "source_ip": source_ip,
                    "request_count": int(profile.get("request_count", 0)),
                    "last_seen": last_seen,
                    "last_host": profile.get("last_host"),
                    "last_destination_ip": profile.get("last_destination_ip"),
                    "last_destination_port": profile.get("last_destination_port"),
                }
            )

        active_clients.sort(key=lambda item: str(item.get("last_seen", "")), reverse=True)
        return active_clients

    async def drop_connections_for_domain(self, domain: Optional[str]) -> int:
        normalized_domain = self._normalize_domain(domain)
        if not normalized_domain:
            return 0

        dropped_connections = 0

        for connection in list(self.active_connections):
            host = self._normalize_domain(str(connection.get("destination_host") or ""))
            if not host or not self._domain_matches(host, normalized_domain):
                continue

            dropped_connections += 1
            for writer_key in ("client_writer", "remote_writer"):
                writer = connection.get(writer_key)
                if isinstance(writer, asyncio.StreamWriter):
                    try:
                        writer.close()
                    except Exception:
                        pass

        return dropped_connections

    def _record_client_activity(
        self,
        source_ip: Optional[str],
        destination_host: Optional[str],
        destination_port: Optional[int],
        destination_ip: Optional[str],
    ) -> None:
        # The dashboard's device view reads from this lightweight activity table
        # instead of scanning the full packet history every refresh.
        if not source_ip:
            return

        profile = self.client_activity.setdefault(
            source_ip,
            {
                "request_count": 0,
                "last_seen": None,
                "last_host": None,
                "last_destination_ip": None,
                "last_destination_port": None,
            },
        )
        profile["request_count"] = int(profile.get("request_count", 0)) + 1
        profile["last_seen"] = datetime.now().isoformat()
        profile["last_host"] = destination_host
        profile["last_destination_ip"] = destination_ip
        profile["last_destination_port"] = destination_port

    async def _handle_connectivity_probe(
        self,
        writer: asyncio.StreamWriter,
        destination_host: Optional[str],
        request_path: str,
    ) -> bool:
        # Independent helper: phones and laptops probe a few well-known URLs to
        # decide whether the network has internet. We answer those locally so
        # proxy mode does not create a false "no internet" state.
        normalized_host = self._normalize_domain(destination_host)
        normalized_path = request_path or "/"

        if normalized_host in {"connectivitycheck.gstatic.com", "connectivitycheck.android.com"}:
            if normalized_path.startswith("/generate_204"):
                await self._send_response(writer, 204, "No Content")
                return True

        if normalized_host in {"captive.apple.com"}:
            body = (
                "<HTML><HEAD><TITLE>Success</TITLE></HEAD>"
                "<BODY>Success</BODY></HTML>"
            )
            await self._send_response(
                writer,
                200,
                "OK",
                body=body,
                content_type="text/html; charset=utf-8",
            )
            return True

        if normalized_host in {"www.msftconnecttest.com", "msftconnecttest.com"}:
            await self._send_response(
                writer,
                200,
                "OK",
                body="Microsoft Connect Test",
                content_type="text/plain; charset=utf-8",
            )
            return True

        if normalized_host in {"detectportal.firefox.com"}:
            await self._send_response(
                writer,
                200,
                "OK",
                body="success\n",
                content_type="text/plain; charset=utf-8",
            )
            return True

        if normalized_host in {"nmcheck.gnome.org", "networkcheck.kde.org"}:
            await self._send_response(
                writer,
                204,
                "No Content",
            )
            return True

        if normalized_host in {"connect.rom.miui.com", "connectivitycheck.platform.hicloud.com"}:
            await self._send_response(
                writer,
                204,
                "No Content",
            )
            return True

        return False

    def _register_active_connection(
        self,
        destination_host: Optional[str],
        client_writer: asyncio.StreamWriter,
        remote_writer: asyncio.StreamWriter,
    ) -> dict[str, object]:
        connection_entry = {
            "destination_host": self._normalize_domain(destination_host),
            "client_writer": client_writer,
            "remote_writer": remote_writer,
        }
        self.active_connections.append(connection_entry)
        return connection_entry

    def _unregister_active_connection(self, connection_entry: dict[str, object]) -> None:
        if connection_entry in self.active_connections:
            self.active_connections.remove(connection_entry)

    @staticmethod
    def _rebuild_http_request(
        method: str,
        path: str,
        version: str,
        headers: dict[str, str],
    ) -> bytes:
        header_lines = [f"{method} {path} {version}"]
        for key, value in headers.items():
            header_name = "-".join(part.capitalize() for part in key.split("-"))
            header_lines.append(f"{header_name}: {value}")
        return ("\r\n".join(header_lines) + "\r\n\r\n").encode("iso-8859-1", errors="ignore")

    @staticmethod
    async def _send_response(
        writer: asyncio.StreamWriter,
        status_code: int,
        message: str,
        body: Optional[str] = None,
        content_type: str = "text/plain; charset=utf-8",
    ) -> None:
        encoded_body = (body or "").encode("utf-8")
        response = (
            f"HTTP/1.1 {status_code} {message}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(encoded_body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii") + encoded_body
        writer.write(response)
        await writer.drain()
        writer.close()

    @staticmethod
    async def _send_error(
        writer: asyncio.StreamWriter,
        status_code: int,
        message: str,
        body: Optional[str] = None,
        content_type: str = "text/plain; charset=utf-8",
    ) -> None:
        await MobileProxyService._send_response(
            writer,
            status_code,
            message,
            body=body,
            content_type=content_type,
        )

    @staticmethod
    async def _send_blocked_response(writer: asyncio.StreamWriter, destination_host: str) -> None:
        scan_info = MitreMappingService.scan_website_threat(destination_host)
        mitre = scan_info.get("mitre_mapping", {})
        stage_label = mitre.get("stage_label", "Stage 3: Initial Access")
        technique_id = mitre.get("technique_id", "T1189")
        technique_name = mitre.get("technique_name", "Drive-by Compromise")
        threat_cat = scan_info.get("threat_category", "Malware / Trojan Threat")
        severity = scan_info.get("severity", "CRITICAL")
        
        body = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>⚠️ Threat Warning - NetGuard Defense</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }}
        body {{ background: #0b0f19; color: #f1f5f9; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }}
        .card {{ background: #131b2e; border: 1px solid #ef4444; border-radius: 16px; max-width: 580px; width: 100%; padding: 32px; box-shadow: 0 20px 50px rgba(239, 68, 68, 0.25); }}
        .header {{ display: flex; align-items: center; gap: 14px; margin-bottom: 20px; }}
        .shield-icon {{ width: 44px; height: 44px; background: rgba(239, 68, 68, 0.15); border: 2px solid #ef4444; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 22px; }}
        .title {{ font-size: 20px; font-weight: 700; color: #f87171; }}
        .subtitle {{ font-size: 13px; color: #94a3b8; margin-top: 2px; }}
        .alert-box {{ background: rgba(239, 68, 68, 0.1); border-left: 4px solid #ef4444; padding: 14px 16px; border-radius: 6px; margin-bottom: 20px; }}
        .alert-box strong {{ color: #fca5a5; display: block; font-size: 14px; margin-bottom: 4px; }}
        .alert-box p {{ font-size: 13px; color: #cbd5e1; line-height: 1.4; }}
        .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 20px; }}
        .stat {{ background: #1e293b; padding: 12px 14px; border-radius: 10px; border: 1px solid #334155; }}
        .stat-label {{ font-size: 11px; text-transform: uppercase; color: #94a3b8; letter-spacing: 0.5px; }}
        .stat-val {{ font-size: 14px; font-weight: 600; color: #e2e8f0; margin-top: 4px; word-break: break-all; }}
        .badge-stage {{ display: inline-block; background: #7c3aed; color: #fff; padding: 3px 8px; border-radius: 6px; font-size: 12px; font-weight: 600; margin-top: 4px; }}
        .badge-sev {{ display: inline-block; background: #dc2626; color: #fff; padding: 3px 8px; border-radius: 6px; font-size: 12px; font-weight: 600; margin-top: 4px; }}
        .actions {{ display: flex; gap: 12px; margin-top: 24px; }}
        .btn {{ flex: 1; padding: 12px; border-radius: 8px; font-size: 14px; font-weight: 600; text-align: center; text-decoration: none; cursor: pointer; border: none; }}
        .btn-primary {{ background: #3b82f6; color: #fff; }}
        .btn-outline {{ background: transparent; border: 1px solid #475569; color: #cbd5e1; }}
        .footer {{ font-size: 11px; color: #64748b; text-align: center; margin-top: 20px; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="header">
            <div class="shield-icon">🛡️</div>
            <div>
                <div class="title">NetGuard Security Interception</div>
                <div class="subtitle">Malicious Website / Threat Vector Blocked</div>
            </div>
        </div>

        <div class="alert-box">
            <strong>⚠️ High-Risk Malicious Activity Prevented</strong>
            <p>Access to <strong>{destination_host}</strong> has been isolated because it matches malicious threat patterns, trojan delivery signatures, or manual blocklist policies.</p>
        </div>

        <div class="grid">
            <div class="stat">
                <div class="stat-label">MITRE ATT&CK Stage</div>
                <div class="badge-stage">{stage_label}</div>
            </div>
            <div class="stat">
                <div class="stat-label">Severity & Risk</div>
                <div class="badge-sev">{severity} RISK</div>
            </div>
            <div class="stat">
                <div class="stat-label">MITRE Technique ID</div>
                <div class="stat-val">{technique_id}</div>
                <div style="font-size: 11px; color: #94a3b8;">{technique_name}</div>
            </div>
            <div class="stat">
                <div class="stat-label">Threat Classification</div>
                <div class="stat-val">{threat_cat}</div>
            </div>
        </div>

        <div class="stat" style="margin-bottom: 20px;">
            <div class="stat-label">Target Hostname</div>
            <div class="stat-val" style="color: #f87171;">{destination_host}</div>
        </div>

        <div class="actions">
            <button class="btn btn-primary" onclick="window.history.back()">⬅ Return to Safety</button>
        </div>

        <div class="footer">
            Protected by NetGuard AI Network Security • Real-Time MITRE ATT&CK Engine
        </div>
    </div>
</body>
</html>"""

        await MobileProxyService._send_error(
            writer,
            403,
            "Forbidden",
            body=body,
            content_type="text/html; charset=utf-8",
        )
        await writer.wait_closed()

    @staticmethod
    def _normalize_domain(value: Optional[str]) -> str:
        return (value or "").strip().lower().rstrip(".")

    @staticmethod
    def _domain_matches(host: str, domain: str) -> bool:
        return host == domain or host.endswith(f".{domain}")
