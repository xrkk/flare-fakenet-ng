# Copyright 2026 Google LLC
"""Structured error codes for the fakenetng-mcp domain tools (P02).

Frozen by sub-plan P02 §3; the codes are protocol-visible strings and must
not be renamed without a sub-plan contract change.
"""

CONTROLLER_IDENTITY_MISSING = 'controller_identity_missing'
CONTROLLER_CONFLICT = 'controller_conflict'
STATE_CONFLICT = 'state_conflict'
OPERATION_BUSY = 'operation_busy'
CONFIG_NOT_FOUND = 'config_not_found'
NAME_CONFLICT = 'name_conflict'
VERSION_CONFLICT = 'version_conflict'
PATH_ESCAPE_BLOCKED = 'path_escape_blocked'
CONFIG_IN_USE = 'config_in_use'
VALIDATION_FAILED = 'validation_failed'
INVALID_REQUEST = 'invalid_request'
BUILTIN_READONLY = 'builtin_readonly'
AUDIT_WRITE_FAILED = 'audit_write_failed'
NOT_ALLOWED_IN_STATE = 'not_allowed_in_state'
INTERNAL_ERROR = 'internal_error'

ALL_CODES = frozenset((
    CONTROLLER_IDENTITY_MISSING, CONTROLLER_CONFLICT, STATE_CONFLICT,
    OPERATION_BUSY, CONFIG_NOT_FOUND, NAME_CONFLICT, VERSION_CONFLICT,
    PATH_ESCAPE_BLOCKED, CONFIG_IN_USE, VALIDATION_FAILED, INVALID_REQUEST,
    BUILTIN_READONLY, AUDIT_WRITE_FAILED, NOT_ALLOWED_IN_STATE,
    INTERNAL_ERROR,
))


class McpError(Exception):

    def __init__(self, code, message, detail=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.detail = detail or {}

    def to_dict(self):
        payload = {'code': self.code, 'message': self.message}
        if self.detail:
            payload['detail'] = self.detail
        return payload
