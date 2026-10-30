import ipaddress
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class AuthStatus(str, Enum):
    success = "success"
    failed = "failed"


class AuthEvent(BaseModel):
    """A single authentication event as reported by an identity provider.

    Identity providers do not all emit the same shape of event, so every
    field below is deliberately explicit rather than assumed from one
    provider's format. Unknown extra fields are rejected rather than
    silently ignored, to catch integration mistakes early.
    """

    model_config = {"extra": "forbid"}

    event_id: str = Field(min_length=1, max_length=128)
    username: str = Field(min_length=1, max_length=256)
    source_ip: str
    timestamp: datetime
    status: AuthStatus
    authentication_method: str = Field(min_length=1, max_length=64)
    user_role: str = Field(default="employee", max_length=64)
    location: str = Field(default="Unknown", max_length=128)
    source: str = Field(min_length=1, max_length=128)

    @field_validator("source_ip")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(f"source_ip is not a valid IP address: {value}") from exc
        return value

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value: str) -> str:
        return value.strip().lower()


class Finding(BaseModel):
    rule: str
    severity_weight: int
    description: str
    mitre_technique_id: str
    mitre_technique_name: str


class IntelResult(BaseModel):
    source: str
    summary: str
    raw: dict


class RiskBand(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CorrelationContext(BaseModel):
    lookback_days: int
    prior_high_critical_incidents_same_user: int
    prior_high_critical_incidents_same_ip: int


class EventIngestResponse(BaseModel):
    event_id: str
    incident_id: Optional[str]
    findings: list[Finding]
    intel: list[IntelResult]
    risk_score: int
    risk_band: RiskBand
    correlation: CorrelationContext


class DecisionRequest(BaseModel):
    approved: bool
    decided_by: str = Field(min_length=1, max_length=128)
    response_action: str = Field(min_length=1, max_length=64)
    notes: Optional[str] = Field(default=None, max_length=1024)


class DecisionResponse(BaseModel):
    incident_id: str
    decision: DecisionRequest
    outcome: str
    simulated: bool = True
