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
from app.logging_config import configure_logging, get_logger
from app.models.db import get_connection, init_db
from app.models.events_store import DuplicateEventError, insert_event
from app.models.idempotency import get_cached_response, store_response
from app.models.schemas import (
    AuthEvent,
    DecisionRequest,
    DecisionResponse,
    EventIngestResponse,
)
from app.risk.correlation import correlate
from app.risk.scoring import band_for, score as score_findings

logger = get_logger(__name__)
limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging(settings.log_level)
    init_db()
    logger.info("startup.complete")
    yield


app = FastAPI(
    title="EL JEFE",
    description="Automated identity threat detection and response",
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


def _require_api_key(expected: str, x_api_key: str) -> None:
    if not expected or x_api_key != expected:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key header")


def require_ingest_key(x_api_key: str = Header(default="")) -> None:
    _require_api_key(settings.ingest_api_key, x_api_key)


def require_decision_key(x_api_key: str = Header(default="")) -> None:
    _require_api_key(settings.decision_api_key, x_api_key)


@app.post("/events", response_model=EventIngestResponse, dependencies=[Depends(require_ingest_key)])
@limiter.limit("30/minute")
def ingest_event(
    event: AuthEvent, request: Request, idempotency_key: str | None = Header(default=None)
) -> EventIngestResponse:
    with get_connection() as conn:
        if idempotency_key:
            cached = get_cached_response(conn, idempotency_key)
            if cached is not None:
                logger.info("events.idempotent_replay", extra={"idempotency_key": idempotency_key})
                return EventIngestResponse(**cached)

        try:
            insert_event(conn, event)
        except DuplicateEventError as exc:
            logger.warning("events.duplicate_event_id", extra={"event_id": event.event_id})
            raise HTTPException(status_code=409, detail=str(exc)) from exc

        intel_results = []
        intel_result, abuse_score = check_ip(
            conn,
            event.source_ip,
            settings.abuseipdb_api_key,
            settings.intel_cache_ttl_minutes,
            max_retries=settings.intel_max_retries,
            retry_backoff_seconds=settings.intel_retry_backoff_seconds,
        )
        intel_results.append(intel_result)

        if looks_like_domain(event.source):
            intel_results.append(
                check_domain(
                    conn,
                    event.source,
                    settings.virustotal_api_key,
                    settings.intel_cache_ttl_minutes,
                    max_retries=settings.intel_max_retries,
                    retry_backoff_seconds=settings.intel_retry_backoff_seconds,
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
        correlation = correlate(conn, event, settings.incident_correlation_lookback_days)

        incident_id = None
        if risk_band in INCIDENT_BANDS:
            incident_id = create_incident(
                conn, event.event_id, findings, intel_results, risk_score, risk_band
            )
            logger.info(
                "events.incident_created",
                extra={"event_id": event.event_id, "incident_id": incident_id, "risk_band": risk_band.value},
            )

        logger.info(
            "events.scored",
            extra={"event_id": event.event_id, "risk_score": risk_score, "risk_band": risk_band.value},
        )

        result = EventIngestResponse(
            event_id=event.event_id,
            incident_id=incident_id,
            findings=findings,
            intel=intel_results,
            risk_score=risk_score,
            risk_band=risk_band,
            correlation=correlation,
        )

        if idempotency_key:
            store_response(conn, idempotency_key, result.model_dump(mode="json"))

        return result


@app.get("/incidents/{incident_id}", dependencies=[Depends(require_ingest_key)])
@limiter.limit("60/minute")
def read_incident(incident_id: str, request: Request) -> dict:
    with get_connection() as conn:
        incident = get_incident(conn, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@app.post(
    "/incidents/{incident_id}/decision",
    response_model=DecisionResponse,
    dependencies=[Depends(require_decision_key)],
)
@limiter.limit("20/minute")
def decide_incident(incident_id: str, decision: DecisionRequest, request: Request) -> DecisionResponse:
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
        logger.info(
            "incidents.decided",
            extra={
                "incident_id": incident_id,
                "approved": decision.approved,
                "response_action": decision.response_action,
                "decided_by": decision.decided_by,
            },
        )

    return DecisionResponse(incident_id=incident_id, decision=decision, outcome=outcome)
