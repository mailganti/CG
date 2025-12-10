"""
Dual Authentication Module for FastAPI
=======================================

Supports both Smart Card (client certificate) and Windows Native Authentication.
Works with the ssl_proxy.py custom proxy which passes identity via headers.

Headers expected from proxy:
    - X-Auth-User: Authenticated username (DOMAIN\\user or user@domain)
    - X-Auth-Method: Authentication method used (smartcard, wna)
    - X-Client-DN: Full certificate DN (for smart card auth)

Usage:
    from auth import auth_router, get_current_user, require_auth, DualAuthUser
    
    app.include_router(auth_router, prefix="/api")
    
    @app.get("/api/protected")
    async def protected(user: DualAuthUser = Depends(require_auth)):
        return {"user": user.username}
"""

from fastapi import APIRouter, Request, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, List
import re
import logging

logger = logging.getLogger(__name__)


# =============================================================================
# Configuration
# =============================================================================

class AuthConfig:
    """Authentication configuration"""
    # Headers from proxy
    AUTH_USER_HEADER = "X-Auth-User"
    AUTH_METHOD_HEADER = "X-Auth-Method"
    CERT_DN_HEADER = "X-Client-DN"
    
    # Behavior
    REQUIRE_AUTH = True  # Reject requests without authentication
    ALLOW_ANONYMOUS = False  # Allow anonymous access to some endpoints
    
    # Admin groups (users in these groups have admin privileges)
    ADMIN_GROUPS = ["Domain Admins", "Orchestration-Admins"]
    
    # Trusted proxy IPs (only accept auth headers from these)
    TRUSTED_PROXIES = ["127.0.0.1", "::1"]  # Add your proxy IP


AUTH_CONFIG = AuthConfig()


# =============================================================================
# Models
# =============================================================================

class DualAuthUser(BaseModel):
    """Authenticated user from either Smart Card or Windows Auth"""
    username: str  # Just the username part
    domain: Optional[str] = None  # Domain name
    full_identity: str  # Full identity string (DOMAIN\\user)
    auth_method: str  # "smartcard" or "wna"
    display_name: Optional[str] = None  # Friendly name
    cert_dn: Optional[str] = None  # Certificate DN (smart card only)
    groups: List[str] = []  # AD groups (if available)
    
    class Config:
        json_schema_extra = {
            "example": {
                "username": "jsmith",
                "domain": "CORP",
                "full_identity": "CORP\\jsmith",
                "auth_method": "smartcard",
                "display_name": "John Smith",
                "cert_dn": "CN=John Smith, O=Corp, C=US",
                "groups": ["Domain Users", "Developers"]
            }
        }


class AuthStatus(BaseModel):
    """Authentication status response"""
    authenticated: bool
    username: Optional[str] = None
    domain: Optional[str] = None
    auth_method: Optional[str] = None


# =============================================================================
# Helper Functions
# =============================================================================

def parse_identity(identity: str) -> tuple[str, Optional[str]]:
    """
    Parse identity string into (username, domain).
    
    Supports:
        - DOMAIN\\username -> (username, DOMAIN)
        - username@domain.com -> (username, DOMAIN)
        - username -> (username, None)
    """
    if not identity:
        return ("", None)
    
    # DOMAIN\username format
    if '\\' in identity:
        parts = identity.split('\\', 1)
        return (parts[1], parts[0].upper())
    
    # username@domain format (UPN)
    if '@' in identity:
        parts = identity.split('@', 1)
        domain = parts[1].split('.')[0].upper()  # Extract short domain
        return (parts[0], domain)
    
    return (identity, None)


def extract_cn_from_dn(dn: str) -> Optional[str]:
    """Extract Common Name from certificate DN for display name"""
    if not dn:
        return None
    
    patterns = [
        r'CN=([^,/]+)',
        r'/CN=([^/]+)',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, dn, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    
    return None


def is_trusted_proxy(request: Request) -> bool:
    """Check if request comes from a trusted proxy"""
    client_ip = request.client.host if request.client else None
    
    # In production, validate the proxy IP
    if AUTH_CONFIG.TRUSTED_PROXIES:
        return client_ip in AUTH_CONFIG.TRUSTED_PROXIES
    
    return True  # Allow all if no trusted proxies configured


# =============================================================================
# Dependency Injection
# =============================================================================

async def get_current_user(request: Request) -> Optional[DualAuthUser]:
    """
    Extract authenticated user from proxy headers.
    Returns None if not authenticated (use require_auth for mandatory auth).
    """
    # Get auth headers
    identity = request.headers.get(AUTH_CONFIG.AUTH_USER_HEADER)
    auth_method = request.headers.get(AUTH_CONFIG.AUTH_METHOD_HEADER, "unknown")
    cert_dn = request.headers.get(AUTH_CONFIG.CERT_DN_HEADER)
    
    if not identity:
        return None
    
    # Validate trusted proxy
    if not is_trusted_proxy(request):
        logger.warning(f"Auth header from untrusted source: {request.client.host}")
        return None
    
    # Parse identity
    username, domain = parse_identity(identity)
    
    if not username:
        return None
    
    # Build display name
    display_name = None
    if cert_dn:
        display_name = extract_cn_from_dn(cert_dn)
    if not display_name:
        # Convert username to display name (john.smith -> John Smith)
        display_name = username.replace('.', ' ').replace('_', ' ').title()
    
    return DualAuthUser(
        username=username,
        domain=domain,
        full_identity=identity,
        auth_method=auth_method,
        display_name=display_name,
        cert_dn=cert_dn,
        groups=[]  # Would need LDAP lookup to populate
    )


async def require_auth(request: Request) -> DualAuthUser:
    """
    Require authentication - raises 401 if not authenticated.
    Use as dependency for protected endpoints.
    """
    user = await get_current_user(request)
    
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Negotiate"}
        )
    
    return user


async def require_admin(user: DualAuthUser = Depends(require_auth)) -> DualAuthUser:
    """
    Require admin privileges.
    Checks if user is in any admin group.
    """
    user_groups_lower = [g.lower() for g in user.groups]
    
    for admin_group in AUTH_CONFIG.ADMIN_GROUPS:
        if admin_group.lower() in user_groups_lower:
            return user
    
    # For now, also allow if domain is present (basic check)
    # In production, implement proper group checking via LDAP
    if user.domain:
        logger.info(f"Admin access granted to {user.full_identity} (domain user)")
        return user
    
    raise HTTPException(
        status_code=403,
        detail="Administrator privileges required"
    )


# =============================================================================
# Auth Router
# =============================================================================

auth_router = APIRouter(prefix="/auth", tags=["Authentication"])


@auth_router.get("/me", response_model=DualAuthUser)
async def get_me(user: DualAuthUser = Depends(require_auth)):
    """
    Get current authenticated user information.
    
    Returns user details from either Smart Card or Windows authentication.
    """
    return user


@auth_router.get("/check", response_model=AuthStatus)
async def check_auth(user: Optional[DualAuthUser] = Depends(get_current_user)):
    """
    Check authentication status without requiring auth.
    
    Useful for frontend to determine if user is logged in.
    """
    if user:
        return AuthStatus(
            authenticated=True,
            username=user.username,
            domain=user.domain,
            auth_method=user.auth_method
        )
    
    return AuthStatus(authenticated=False)


@auth_router.get("/debug")
async def debug_auth(request: Request):
    """
    Debug endpoint showing all auth-related headers.
    
    WARNING: Disable in production!
    """
    auth_headers = {}
    for header in [AUTH_CONFIG.AUTH_USER_HEADER, 
                   AUTH_CONFIG.AUTH_METHOD_HEADER, 
                   AUTH_CONFIG.CERT_DN_HEADER]:
        value = request.headers.get(header)
        if value:
            auth_headers[header] = value
    
    return {
        "client_ip": request.client.host if request.client else None,
        "is_trusted_proxy": is_trusted_proxy(request),
        "auth_headers": auth_headers,
        "all_headers": dict(request.headers)  # Remove in production!
    }


# =============================================================================
# Example Integration
# =============================================================================

"""
Example FastAPI app with dual auth:

from fastapi import FastAPI
from auth import auth_router, require_auth, DualAuthUser, Depends

app = FastAPI(title="Orchestration API")

# Include auth routes
app.include_router(auth_router, prefix="/api")

# Public endpoint (no auth required)
@app.get("/api/health")
async def health():
    return {"status": "healthy"}

# Protected endpoint
@app.get("/api/workflows")
async def list_workflows(user: DualAuthUser = Depends(require_auth)):
    # user.username, user.domain, user.auth_method available
    return {"workflows": [...], "user": user.username}

# Admin-only endpoint
@app.delete("/api/workflows/{id}")
async def delete_workflow(id: str, user: DualAuthUser = Depends(require_admin)):
    return {"deleted": id, "by": user.username}
"""
