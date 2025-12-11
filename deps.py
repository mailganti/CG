"""
controller/deps.py

Authentication / Authorization dependencies for the Orchestration System.
Uses ONLY Smart Card / Windows Auth forwarded headers, merged with DB user roles.
"""

from __future__ import annotations

import os
import re
import logging
from datetime import datetime
from typing import Optional, Dict, Any

import jwt
from fastapi import Request, Header, Depends, HTTPException, status

from controller.db.db import get_db

logger = logging.getLogger(__name__)

APPROVER_JWT_SECRET = os.getenv("APPROVER_JWT_SECRET", "change-me")
APPROVER_JWT_ALGO = os.getenv("APPROVER_JWT_ALGO", "HS256")


# -------------------------------------------------------------
# Identity Normalization
# -------------------------------------------------------------
def normalize_identity(raw: str) -> str:
    """
    Convert arbitrary identity strings into a clean username.

    Examples:
      'U\\Rajesh Mudiganti (affiliate)' → 'Rajesh Mudiganti'
      'DOMAIN\\jsmith' → 'jsmith'
      'jsmith@acme.com' → 'jsmith'
    """
    if not raw:
        return ""

    s = raw.strip()

    # Remove quotes
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        s = s[1:-1].strip()

    # Remove any trailing parentheses text
    s = re.sub(r"\s*\([^)]*\)\s*$", "", s).strip()

    # DOMAIN\username → username
    if "\\" in s:
        s = s.split("\\", 1)[1].strip()

    # user@domain.com → user
    if "@" in s:
        s = s.split("@", 1)[0]

    # Remove weird U\ prefix again if still present
    s = re.sub(r"^[A-Za-z]\\", "", s).strip()

    # Collapse double spaces
    s = re.sub(r"\s+", " ", s)

    return s


# -------------------------------------------------------------
# Build runtime user from proxy headers + DB role merge
# -------------------------------------------------------------
def get_runtime_user_from_request(request: Request) -> Optional[Dict[str, Any]]:
    """
    Build a unified user object:
        - read identity from Smart Card / WNA headers
        - normalize it
        - merge with DB user for role + user_id

    Returns None if no identity found.
    """
    hdr_user = (
        request.headers.get("X-Auth-User")
        or request.headers.get("X-Forwarded-User")
        or request.headers.get("X-Remote-User")
    )

    if not hdr_user:
        return None

    normalized = normalize_identity(hdr_user)

    runtime_user = {
        "username": normalized,
        "display_name": normalized.replace(".", " ").replace("_", " ").title(),
        "role": None,
        "user_id": None,
        "auth_method": request.headers.get("X-Auth-Method") or "proxy",
    }

    # Merge with DB user record
    try:
        db = get_db()
        user = db.get_user_by_username(normalized)
        if user:
            runtime_user["role"] = user.get("role")
            runtime_user["user_id"] = user.get("user_id") or user.get("id")
            runtime_user["display_name"] = user.get("full_name") or runtime_user["display_name"]
    except Exception:
        logger.exception("Failed to merge user with DB")

    return runtime_user


# -------------------------------------------------------------
# Dependencies
# -------------------------------------------------------------
def require_authenticated_user(request: Request) -> Dict[str, Any]:
    user = get_runtime_user_from_request(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def require_admin(request: Request, user=Depends(require_authenticated_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def require_approver(request: Request, user=Depends(require_authenticated_user)):
    if user.get("role") not in ("approver", "admin"):
        raise HTTPException(status_code=403, detail="Approver access required")
    return user


# -------------------------------------------------------------
# Approver JWT for workflow approvals
# -------------------------------------------------------------
def verify_approver_jwt(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization:
        raise HTTPException(401, "Missing Authorization header")

    if not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Invalid Authorization header")

    token = authorization.split(" ", 1)[1].strip()

    try:
        payload = jwt.decode(token, APPROVER_JWT_SECRET, algorithms=[APPROVER_JWT_ALGO])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Approver token expired")
    except Exception:
        raise HTTPException(401, "Invalid approver token")

    if payload.get("role") not in ("approver", "admin"):
        raise HTTPException(403, "Approver role required")

    return payload


# -------------------------------------------------------------
# Execution Token Dependency (One-Time Tokens)
# -------------------------------------------------------------
def require_execution_token(workflow_id: str):
    def _dep(
        token: Optional[str] = Header(None, alias="X-Execution-Token"),
        user=Depends(require_authenticated_user),
    ):
        if not token:
            raise HTTPException(403, "Execution token required")

        db = get_db()
        token_row = db.get_execution_token_by_value(token)
        if not token_row:
            raise HTTPException(403, "Invalid execution token")

        # workflow match
        if str(token_row.get("workflow_id")) != str(workflow_id):
            raise HTTPException(403, "Token not valid for this workflow")

        # used?
        if token_row.get("used"):
            raise HTTPException(403, "Token already used")

        # expired?
        expires_at = token_row.get("expires_at")
        if expires_at:
            try:
                exp = datetime.fromisoformat(expires_at)
                if exp < datetime.utcnow():
                    raise HTTPException(403, "Token expired")
            except Exception:
                logger.error("Invalid expires_at format: %s", expires_at)

        # mark used
        ok = db.mark_execution_token_used(token_row["id"], user["username"])
        if not ok:
            raise HTTPException(403, "Token could not be consumed")

        return token_row

    return _dep
