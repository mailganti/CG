
# controller/deps.py - With Session + Token Authentication

"""
Authentication and authorization dependencies
Supports: API tokens (admin/agent) AND web session cookies
"""

from fastapi import Header, HTTPException, status, Depends, Request
from typing import Optional
import logging

logger = logging.getLogger(__name__)

# Import database
from controller.db.db import get_db


def verify_token(
    request: Request,
    x_admin_token: Optional[str] = Header(None),
    x_agent_token: Optional[str] = Header(None)
) -> dict:
    """
    Verify authentication via token OR session
    
    Supports three authentication methods:
    1. API admin tokens (X-Admin-Token header)
    2. API agent tokens (X-Agent-Token header)  
    3. Web session cookies (from login)
    """
    db = get_db()
    
    # Method 1: Check admin token (API authentication)
    if x_admin_token:
        token = db.get_token_by_value(x_admin_token)
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid admin token"
            )
        
        if token.get('revoked'):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked"
            )
        
        # Update last used
        db.update_token_last_used(token['token_name'])
        
        return {
            'token_name': token['token_name'],
            'role': token.get('role', 'viewer'),
            'token_type': 'admin',
            'auth_method': 'api_token'
        }
    
    # Method 2: Check agent token (Agent authentication)
    elif x_agent_token:
        token = db.get_token_by_value(x_agent_token)
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid agent token"
            )
        
        if token.get('revoked'):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked"
            )
        
        # Verify it's actually an agent token
        if token.get('role') != 'agent':
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Token is not an agent token"
            )
        
        # Update last used
        db.update_token_last_used(token['token_name'])
        
        return {
            'token_name': token['token_name'],
            'role': 'agent',
            'token_type': 'agent',
            'auth_method': 'api_token'
        }
    
    # Method 3: Check session cookie (Web authentication)
    else:
        # Try to get user from session
        try:
            from controller.auth.web_auth import get_current_user_from_session
            
            session_cookie = request.cookies.get("orchestration_session")
            user = get_current_user_from_session(request, session_cookie)
            
            if user:
                # User authenticated via web session
                logger.info(f"Web user authenticated: {user['username']} (role: {user['role']})")
                return {
                    'username': user['username'],
                    'role': user['role'],
                    'token_type': 'session',
                    'auth_method': 'web_session',
                    'user_id': user.get('user_id'),
                    'full_name': user.get('full_name')
                }
        except ImportError:
            # web_auth module not available
            pass
        except Exception as e:
            logger.error(f"Session authentication error: {e}")
        
        # No valid authentication method found
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No authentication token provided"
        )


def require_role(*allowed_roles: str):
    """
    Dependency to require specific roles
    
    Works with both API tokens and web sessions
    
    Usage:
        @router.get("/admin-only")
        async def admin_endpoint(user: dict = Depends(require_role("admin"))):
            ...
    """
    def role_checker(user: dict = Depends(verify_token)) -> dict:
        if user['role'] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of: {', '.join(allowed_roles)}"
            )
        return user
    
    return role_checker


def require_admin(user: dict = Depends(verify_token)) -> dict:
    """
    Require admin role
    
    Works with both API tokens and web sessions
    """
    if user['role'] != 'admin':
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return user


def require_agent(user: dict = Depends(verify_token)) -> dict:
    """
    Require agent role (for agent-only endpoints like heartbeat)
    
    Only works with agent API tokens
    """
    if user['role'] != 'agent':
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Agent access required"
        )
    return user


def require_approver(user: dict = Depends(verify_token)) -> dict:
    """
    Require approver or admin role
    
    Works with both API tokens and web sessions
    """
    if user['role'] not in ['approver', 'admin']:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Approver or admin access required"
        )
    return user


# Deprecated - for backward compatibility
def verify_admin_token(x_admin_token: str = Header(...)) -> dict:
    """
    DEPRECATED: Use verify_token with require_admin instead
    
    This function is kept for backward compatibility but will be removed
    """
    logger.warning("Using deprecated verify_admin_token - use verify_token with require_admin instead")
    db = get_db()
    
    token = db.get_token_by_value(x_admin_token)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin token"
        )
    
    if token.get('revoked'):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked"
        )
    
    # Update last used
    db.update_token_last_used(token['token_name'])
    
    return {
        'token_name': token['token_name'],
        'role': token.get('role', 'viewer')
    }
