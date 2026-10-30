from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.config import settings
from app.detection.engine import run_detection
from app.incidents import response as response_sim
from app.incidents.store import INCIDENT_BANDS, create_incident, get_incident, record_decision
from app.intelligence.abuseipdb import check_ip
from app.intelligence.virustotal import check_domain, looks_like_domain
from app.models.db import get_connection, init_db
from app.models.events_store import DuplicateEventError, insert_event
from app.models.schemas import (
    AuthEvent,
    DecisionRequest,
    DecisionResponse,
    EventIngestResponse,
)
from app.risk.scoring import band_for, score as score_findings

limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="SENTINEL",
    description="Automated identity threat detection and response",
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


def require_api_key(x_api_key: str = Header(default="")) -> None:
    if not settings.api_key or x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key header")


@app.post("/events", response_model=EventIngestResponse, dependencies=[Depends(require_api_key)])
@limiter.limit("30/minute")
def ingest_event(event: AuthEvent, request: Request) -> EventIngestResponse:
    with get_connection() as conn:
        try:
            insert_event(conn, event)
        except DuplicateEventError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

        intel_results = []
        intel_result, abuse_score = check_ip(
            conn, event.source_ip, settings.abuseipdb_api_key, settings.intel_cache_ttl_minutes
        )
        intel_results.append(intel_result)

        if looks_like_domain(event.source):
            intel_results.append(
                check_domain(
                    conn, event.source, settings.virustotal_api_key, settings.intel_cache_ttl_minutes
                )
            )

        findings = run_detection(
            conn,
            event,
            abuse_confidence_score=abuse_score,
            failed_login_threshold=settings.failed_login_threshold,
            spray_threshold=settings.spray_distinct_accounts_threshold,
            abuseipdb_threshold=settings.abuseipdb_score_threshold,
            window_minutes=settings.correlation_window_minutes,
        )

        risk_score = score_findings(findings)
        risk_band = band_for(risk_score)

        incident_id = None
        if risk_band in INCIDENT_BANDS:
            incident_id = create_incident(
                conn, event.event_id, findings, intel_results, risk_score, risk_band
            )

        return EventIngestResponse(
            event_id=event.event_id,
            incident_id=incident_id,
            findings=findings,
            intel=intel_results,
            risk_score=risk_score,
            risk_band=risk_band,
        )


@app.get("/incidents/{incident_id}", dependencies=[Depends(require_api_key)])
def read_incident(incident_id: str) -> dict:
    with get_connection() as conn:
        incident = get_incident(conn, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@app.post(
    "/incidents/{incident_id}/decision",
    response_model=DecisionResponse,
    dependencies=[Depends(require_api_key)],
)
def decide_incident(incident_id: str, decision: DecisionRequest) -> DecisionResponse:
    with get_connection() as conn:
        incident = get_incident(conn, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")

        outcome = response_sim.simulate(
            decision.response_action,
            incident["username"],
            incident["source_ip"],
            decision.approved,
        )
        record_decision(conn, incident_id, decision, outcome)

    return DecisionResponse(incident_id=incident_id, decision=decision, outcome=outcome)
