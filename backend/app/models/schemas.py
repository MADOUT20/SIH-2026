from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

# These schemas are typed data containers. They describe what a packet,
# threat, notification, or settings object should look like.
class Packet(BaseModel):
    id: int
    timestamp: datetime
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    size_bytes: int
    flags: str

class Threat(BaseModel):
    id: int
    timestamp: datetime
    type: str
    severity: str
    source_ip: str
    destination_ip: str
    description: str
    confidence_score: float
    status: str

class TrafficData(BaseModel):
    timestamp: datetime
    incoming_mbps: float
    outgoing_mbps: float
    total_connections: int
    active_connections: int

class Notification(BaseModel):
    id: int
    timestamp: datetime
    type: str
    title: str
    message: str
    severity: str
    read: bool

class User(BaseModel):
    id: int
    username: str
    email: str
    role: str
    status: str
    last_login: datetime

class Flow(BaseModel):
    flow_id: str
    timestamp: datetime
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    protocol: str
    start_time: datetime
    end_time: datetime
    total_packets: int
    total_bytes: int
    packets_forward: int
    bytes_forward: int
    packets_backward: int
    bytes_backward: int
    duration: float
    avg_packet_size: float
    status: str = "active"
