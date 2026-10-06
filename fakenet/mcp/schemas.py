# Copyright 2026 Google LLC
"""Typed output models for the public tool surface (T003 §B).

Every model keeps ``extra='allow'`` so the production dict returns pass
through SDK validation unchanged — stable top-level fields carry explicit
types/nullability, nested known structures (rows, cursors, config
identities, command cache views) are typed too, and genuinely open
payloads (health, detail) stay open dicts. Fields default to None so the
domain-error shapes (which carry ``error`` and may omit success fields)
validate equally; errors are never coerced into success defaults.
"""

from pydantic import BaseModel, ConfigDict, Field


class _Open(BaseModel):
    model_config = ConfigDict(extra='allow')


class ErrorObject(_Open):
    code: str | None = None
    message: str | None = None


class PingResult(_Open):
    service: str | None = None
    version: str | None = None
    protocol: str | None = None
    controller_header: str | None = None
    build_identity: dict | None = None


class HealthDetail(_Open):
    pass


class ConfigIdentity(_Open):
    name: str | None = None
    sha256: str | None = None
    builtin: bool | None = None


class ServiceStatus(_Open):
    state: str | None = None
    state_version: int | None = None
    run_id: str | None = None
    controller: str | None = None
    failure_reason: str | None = None
    config_identity: ConfigIdentity | None = None
    last_run_outcome: str | None = None
    health: HealthDetail | None = None
    service: str | None = None
    error: ErrorObject | None = None


class StatusResponse(ServiceStatus):
    """get_status: the full current snapshot plus service identity."""


class EventEntry(_Open):
    timestamp: float | None = None
    kind: str | None = None
    epoch: str | None = None
    seq: int | None = None


class EventsResponse(_Open):
    events: list[EventEntry] = Field(default_factory=list)
    epoch: str | None = None
    next_cursor: str | None = None
    has_more: bool | None = None
    gap: bool | None = None
    reset_required: bool | None = None
    oldest_seq: int | None = None
    latest_seq: int | None = None
    limit: int | None = None
    run_id: str | None = None
    error: ErrorObject | None = None


class ConfigsResponse(_Open):
    configs: list[dict] = Field(default_factory=list)
    error: ErrorObject | None = None


class ValidateResponse(_Open):
    valid: bool | None = None
    sections: list[str] | None = None
    error: ErrorObject | None = None


class ReadConfigResponse(ConfigIdentity):
    content: str | None = None
    error: ErrorObject | None = None


class ArtifactRow(_Open):
    path: str | None = None
    type: str | None = None
    size: int | None = None
    complete: bool | None = None
    sha256: str | None = None


class ArtifactQuery(_Open):
    run_id: str | None = None
    artifact_type: str | None = None


class ArtifactsResponse(_Open):
    artifacts: list[ArtifactRow] = Field(default_factory=list)
    query: ArtifactQuery | None = None
    matched_count: int | None = None
    # list_artifacts reports diagnostic-surface failures as a plain string.
    error: ErrorObject | str | None = None


class ConfigReceipt(_Open):
    name: str | None = None
    sha256: str | None = None
    builtin: bool | None = None
    deleted: bool | None = None


class CommandCacheResponse(_Open):
    """in_progress placeholder or the saved final response of a command."""
    state: str | None = None
    state_version: int | None = None
    run_id: str | None = None
    changed: bool | None = None
    command_id: str | None = None
    in_progress: bool | None = None
    last_run_outcome: str | None = None
    config_identity: ConfigIdentity | None = None
    config_result: ConfigReceipt | None = None


class CommandStatusResponse(_Open):
    command_id: str | None = None
    status: str | None = None
    cache_scope: str | None = None
    cache_epoch: str | None = None
    persistent: bool | None = None
    response: CommandCacheResponse | None = None
    command_error: ErrorObject | None = None
    unknown_detail: str | None = None
    error: ErrorObject | None = None


class WaitStatusResponse(_Open):
    matched: bool | None = None
    timed_out: bool | None = None
    elapsed_seconds: float | None = None
    status: ServiceStatus | None = None
    error: ErrorObject | None = None


class EventPage(EventsResponse):
    """The events sub-query embedded in an overview (same page shape)."""


class ArtifactSubQuery(ArtifactsResponse):
    selection_note: str | None = None
    error: ErrorObject | str | None = None


class RunOverviewResponse(_Open):
    selected_run_id: str | None = None
    selection: str | None = None
    service_status: ServiceStatus | None = None
    events_query: EventPage | None = None
    artifacts_query: ArtifactSubQuery | None = None
    status_before_version: int | None = None
    status_after_version: int | None = None
    consistent: bool | None = None
    partial: bool | None = None
    # The aggregate names failing sub-queries as a plain string ('... failed').
    error: ErrorObject | str | None = None


class MutationResponse(_Open):
    """Lifecycle and configuration mutations plus error_response shapes."""
    state: str | None = None
    state_version: int | None = None
    run_id: str | None = None
    changed: bool | None = None
    error: ErrorObject | None = None
    command_id: str | None = None
    in_progress: bool | None = None
    replayed: bool | None = None
    bound_run_id: str | None = None
    last_run_outcome: str | None = None
    config_identity: ConfigIdentity | None = None
    config_result: ConfigReceipt | None = None
