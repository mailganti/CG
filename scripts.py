# controller/routes/scripts.py - Filesystem-based script execution with SSL support
"""
Script management routes with filesystem-based execution
Scripts are stored on the server filesystem and referenced by ID in database
Execute scripts: POST /api/scripts/{script_id}/execute

Also used by workflows.execute_workflow, which builds an ExecuteScriptRequest
and calls execute_script() directly.
"""

from fastapi import APIRouter, HTTPException, Depends, Query, BackgroundTasks
from pydantic import BaseModel, Field, validator
from typing import Optional, Dict, Any, List
import logging
import os
import re
import asyncio
import subprocess
import httpx
import subprocess
import logging
import json
from pathlib import Path

from controller.db.db import get_db
from controller.deps import verify_token, require_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scripts", tags=["scripts"])

# SSL Configuration - ENABLED BY DEFAULT
SSL_ENABLED = os.getenv("SSL_ENABLED", "true").lower() == "true"
SSL_VERIFY = os.getenv("SSL_VERIFY", "false").lower() == "true"  # False for self-signed certs
SSL_CA_CERTS = os.getenv("SSL_CA_CERTS", "./certs/certChain.pem")

# Script storage configuration
SCRIPTS_BASE_PATH = os.getenv("SCRIPTS_BASE_PATH", "/opt/orchestration/scripts")

# Log SSL configuration at startup
logger.info(f"[SSL] Scripts route - SSL_ENABLED: {SSL_ENABLED}, SSL_VERIFY: {SSL_VERIFY}")


def run_workflow_script(workflow_id: str, workflow: dict, execution_id: int):
    """
    Execute the script referenced by workflow['script_id'].
    Must return a JSON-serializable result dict (or None).
    """
    db = get_db()
    script_id = workflow.get('script_id')
    script = db.get_script(script_id)
    if not script:
        raise RuntimeError(f"Script {script_id} not found")

    script_path = script.get('script_path')
    if not script_path or not os.path.exists(script_path):
        raise RuntimeError(f"Script path missing or not found: {script_path}")

    # For example, run script synchronously and capture output
    proc = subprocess.run([script_path], capture_output=True, text=True, timeout=3600)
    stdout = proc.stdout
    stderr = proc.stderr
    rc = proc.returncode

    # write logs to a file named by execution_id
    log_dir = os.getenv('LOG_DIR', 'logs')
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f"execution_{execution_id}.log")
    with open(log_file, 'w') as f:
        f.write("STDOUT\n")
        f.write(stdout or "")
        f.write("\nSTDERR\n")
        f.write(stderr or "")

    # update execution record with log file path
    db.complete_execution_record(execution_id, status="success" if rc == 0 else "failed", result_json=json.dumps({'rc': rc, 'stdout': stdout, 'stderr': stderr}))
    return {'rc': rc, 'stdout': stdout, 'stderr': stderr}


# Pydantic models
class ScriptRegister(BaseModel):
    script_id: str = Field(..., min_length=2, max_length=100)
    script_path: str = Field(..., min_length=1, max_length=500)
    description: str = Field(default="", max_length=1000)
    timeout: Optional[int] = Field(300, ge=1, le=3600)
    
    @validator('script_id')
    def validate_script_id(cls, v):
        """Script ID must be alphanumeric with hyphens/underscores"""
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Script ID must contain only letters, numbers, hyphens, and underscores')
        return v
    
    @validator('script_path')
    def validate_script_path(cls, v):
        """Basic path validation"""
        if '..' in v:
            raise ValueError('Script path cannot contain ..')
        return v


class ScriptUpdate(BaseModel):
    script_path: Optional[str] = Field(None, min_length=1, max_length=500)
    description: Optional[str] = None
    timeout: Optional[int] = Field(None, ge=1, le=3600)


class ExecuteScriptRequest(BaseModel):
    """
    Request model for executing a script on one or more agents.

    NOTE:
    - Workflows will map workflow.targets -> target_agents here.
    """
    target_agents: List[str] = Field(..., min_items=1, description="Agent names to execute on")
    parameters: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Script parameters")
    timeout: Optional[int] = Field(None, ge=1, le=3600, description="Override script timeout")
    environment: Optional[Dict[str, str]] = Field(default_factory=dict, description="Environment variables")


# Helper functions
def get_absolute_script_path(script_path: str) -> Path:
    """
    Get absolute path to script file
    Ensures script is within SCRIPTS_BASE_PATH for security
    """
    base = Path(SCRIPTS_BASE_PATH).resolve()
    script_file = (base / script_path).resolve()
    
    # Security check: ensure script is within base path
    if not str(script_file).startswith(str(base)):
        raise ValueError(f"Script path must be within {SCRIPTS_BASE_PATH}")
    
    return script_file


def validate_script_exists(script_path: str) -> bool:
    """Check if script file exists on filesystem"""
    try:
        script_file = get_absolute_script_path(script_path)
        return script_file.exists() and script_file.is_file()
    except Exception:
        return False


def get_ssl_verify_config():
    """Get SSL verification config for httpx client"""
    if not SSL_VERIFY:
        return False
    if SSL_CA_CERTS and os.path.exists(SSL_CA_CERTS):
        return SSL_CA_CERTS
    return False  # Fall back to no verification if CA certs not found


async def send_execution_to_agent(
    agent_host: str,
    agent_port: int,
    agent_ssl: bool,
    script_path: str,
    parameters: Dict[str, Any],
    environment: Dict[str, str],
    timeout: int
) -> Dict[str, Any]:
    """
    Send script execution request to agent
    
    Returns execution result from agent
    """
    # Use HTTPS if agent has SSL enabled OR if global SSL is enabled
    use_ssl = agent_ssl or SSL_ENABLED
    protocol = "https" if use_ssl else "http"
    url = f"{protocol}://{agent_host}:{agent_port}/execute"
    
    # Configure SSL verification
    verify_ssl = get_ssl_verify_config()
    
    logger.info(f"[SSL] Connecting to agent: {url} (verify={verify_ssl})")
    
    payload = {
        "script_path": script_path,
        "parameters": parameters,
        "environment": environment,
        "timeout": timeout
    }
    
    try:
        async with httpx.AsyncClient(timeout=timeout + 10, verify=verify_ssl) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            return response.json()
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail=f"Agent execution timeout after {timeout}s")
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Agent communication error: {str(e)}")


# Routes

@router.post("")
@router.post("/")
@router.post("/register")
async def register_script(
    script: ScriptRegister,
    validate_exists: bool = Query(True, description="Check if script file exists"),
    user: dict = Depends(require_admin)
):
    """
    Register a script stored on the server filesystem
    
    **REQUIRES ADMIN TOKEN**
    
    The script file must exist at: {SCRIPTS_BASE_PATH}/{script_path}
    """
    db = get_db()
    
    logger.info(f"Script registration: {script.script_id} -> {script.script_path}")
    
    # Check if script ID already exists
    existing = db.get_script(script.script_id)
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Script '{script.script_id}' already registered"
        )
    
    # Validate script file exists if requested
    if validate_exists:
        if not validate_script_exists(script.script_path):
            abs_path = get_absolute_script_path(script.script_path)
            raise HTTPException(
                status_code=404,
                detail=f"Script file not found: {abs_path}"
            )
    
    try:
        # Register script in database
        registered = db.register_script(
            script_id=script.script_id,
            script_path=script.script_path,
            description=script.description
        )
        
        abs_path = get_absolute_script_path(script.script_path)
        logger.info(
            f"Script registered: {script.script_id} ({abs_path}) by {user.get('token_name', 'unknown')}"
        )
        
        return {
            "message": "Script registered successfully",
            "script": {
                "script_id": script.script_id,
                "script_path": script.script_path,
                "absolute_path": str(abs_path),
                "description": script.description,
                "timeout": script.timeout
            },
            "execute_url": f"/api/scripts/{script.script_id}/execute"
        }
        
    except Exception as e:
        logger.error(f"Error registering script {script.script_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to register script: {str(e)}")


@router.get("")
@router.get("/")
async def list_scripts(
    limit: Optional[int] = Query(None, ge=1, le=1000),
    user: dict = Depends(verify_token)
):
    """
    List all registered scripts
    
    Anyone authenticated can view
    """
    try:
        db = get_db()
        scripts = db.list_scripts(limit=limit)
        
        # Add execute URLs and file existence status
        for script in scripts:
            script['execute_url'] = f"/api/scripts/{script['script_id']}/execute"
            script['file_exists'] = validate_script_exists(script['script_path'])
            if script['file_exists']:
                abs_path = get_absolute_script_path(script['script_path'])
                script['absolute_path'] = str(abs_path)
        
        logger.debug(f"Listed {len(scripts)} scripts (user: {user.get('token_name', 'unknown')})")
        
        return {
            "scripts": scripts,
            "count": len(scripts),
            "base_path": SCRIPTS_BASE_PATH,
            "ssl_enabled": SSL_ENABLED
        }
    except Exception as e:
        logger.error(f"Error listing scripts: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{script_id}")
async def get_script(
    script_id: str,
    user: dict = Depends(verify_token)
):
    """
    Get script details by ID
    
    Anyone authenticated can view
    """
    db = get_db()
    script = db.get_script(script_id)
    
    if not script:
        raise HTTPException(status_code=404, detail=f"Script '{script_id}' not found")
    
    # Add file information
    script['file_exists'] = validate_script_exists(script['script_path'])
    if script['file_exists']:
        abs_path = get_absolute_script_path(script['script_path'])
        script['absolute_path'] = str(abs_path)
        script['file_size'] = abs_path.stat().st_size
    
    script['execute_url'] = f"/api/scripts/{script_id}/execute"
    
    logger.debug(f"Retrieved script: {script_id} (user: {user.get('token_name', 'unknown')})")
    
    return script


@router.post("/{script_id}/execute")
async def execute_script(
    script_id: str,
    request: ExecuteScriptRequest,
    background_tasks: BackgroundTasks,
    user: dict = Depends(require_admin)
):
    """
    Execute script on target agents
    
    **REQUIRES ADMIN TOKEN**
    
    The script file will be read from the server filesystem and executed on target agents.
    
    Usage:
        POST /api/scripts/backup-db/execute
        {
            "target_agents": ["db-server-01", "db-server-02"],
            "parameters": {"database": "production", "backup_dir": "/backups"},
            "timeout": 600
        }
    """
    db = get_db()
    
    logger.info("=== Script Execution Request ===")
    logger.info(f"Script ID: {script_id}")
    logger.info(f"Targets: {request.target_agents}")
    logger.info(f"User: {user.get('token_name', 'unknown')}")
    logger.info(f"SSL Enabled: {SSL_ENABLED}")

    # Get script from database
    script = db.get_script(script_id)
    if not script:
        raise HTTPException(status_code=404, detail=f"Script '{script_id}' not found")
    
    # Verify script file exists
    if not validate_script_exists(script['script_path']):
        abs_path = get_absolute_script_path(script['script_path'])
        raise HTTPException(
            status_code=404,
            detail=f"Script file not found: {abs_path}"
        )
    
    # Get absolute path for execution
    abs_path = get_absolute_script_path(script['script_path'])
    
    # Determine timeout
    timeout = request.timeout or script.get('timeout', 300)
    
    # Verify all target agents exist and are online
    agent_info = []
    for agent_name in request.target_agents:
        agent = db.get_agent(agent_name)
        if not agent:
            raise HTTPException(
                status_code=404,
                detail=f"Agent '{agent_name}' not found"
            )
        
        agent_status = db.get_agent_status(agent_name, timeout_seconds=60)
        if agent_status != 'online':
            logger.warning(f"Agent {agent_name} status: {agent_status}")
        
        # Default to SSL_ENABLED if agent doesn't have ssl_enabled field
        agent_ssl = agent.get('ssl_enabled', SSL_ENABLED)
        
        agent_info.append({
            "name": agent_name,
            "host": agent['host'],
            "port": agent['port'],
            "ssl_enabled": agent_ssl,
            "status": agent_status
        })
    
    # Create workflow_id for tracking this execution batch (not stored in DB yet)
    workflow_id = f"exec_{script_id}_{int(asyncio.get_event_loop().time())}"
    
    results = []
    for agent in agent_info:
        try:
            logger.info(
                f"Sending execution request to {agent['name']} ({agent['host']}:{agent['port']})..."
            )
            logger.info(f"  Protocol: {'https' if agent['ssl_enabled'] else 'http'}")
            logger.info(f"  Status: {agent['status']}")
            
            result = await send_execution_to_agent(
                agent_host=agent['host'],
                agent_port=agent['port'],
                agent_ssl=agent['ssl_enabled'],
                script_path=str(abs_path),
                parameters=request.parameters or {},
                environment=request.environment or {},
                timeout=timeout
            )
            
            results.append({
                "agent": agent['name'],
                "status": "success",
                "result": result,
                "exit_code": result.get('exit_code'),
                "stdout": result.get('stdout', ''),
                "stderr": result.get('stderr', ''),
                "execution_time": result.get('execution_time', 0)
            })
            
            logger.info(
                f"✅ Execution completed on {agent['name']}: exit_code={result.get('exit_code')}"
            )
            
        except HTTPException as e:
            logger.error(f"❌ HTTP error on {agent['name']}: {e.status_code} - {e.detail}")
            results.append({
                "agent": agent['name'],
                "status": "failed",
                "error": f"HTTP {e.status_code}: {e.detail}",
                "error_type": "http_error"
            })
        except Exception as e:
            logger.error(
                f"❌ Execution failed on {agent['name']}: {e}",
                exc_info=True
            )
            results.append({
                "agent": agent['name'],
                "status": "failed",
                "error": str(e),
                "error_type": type(e).__name__
            })
    
    # Count successes and failures
    success_count = sum(1 for r in results if r['status'] == 'success')
    failure_count = len(results) - success_count
    
    failed_agents = [r for r in results if r['status'] == 'failed']
    
    logger.info(f"Execution complete: {success_count} succeeded, {failure_count} failed")
    
    if failed_agents:
        logger.error("Failed agents:")
        for agent_result in failed_agents:
            logger.error(
                f"  - {agent_result['agent']}: {agent_result.get('error', 'Unknown error')}"
            )
    
    return {
        "message": "Script execution completed",
        "script_id": script_id,
        "script_path": script['script_path'],
        "absolute_path": str(abs_path),
        "workflow_id": workflow_id,
        "targets": request.target_agents,
        "success_count": success_count,
        "failure_count": failure_count,
        "results": results,
        "summary": {
            "total": len(results),
            "succeeded": success_count,
            "failed": failure_count,
            "failed_agents": [r['agent'] for r in failed_agents]
        }
    }


@router.put("/{script_id}")
async def update_script(
    script_id: str,
    updates: ScriptUpdate,
    user: dict = Depends(require_admin)
):
    """
    Update script details
    
    **REQUIRES ADMIN TOKEN**
    """
    db = get_db()
    
    script = db.get_script(script_id)
    if not script:
        raise HTTPException(status_code=404, detail=f"Script '{script_id}' not found")
    
    try:
        # Build update data
        update_data = {}
        if updates.script_path is not None:
            # Validate new path exists
            if not validate_script_exists(updates.script_path):
                abs_path = get_absolute_script_path(updates.script_path)
                raise HTTPException(
                    status_code=404,
                    detail=f"Script file not found: {abs_path}"
                )
            update_data['script_path'] = updates.script_path
        
        if updates.description is not None:
            update_data['description'] = updates.description
        
        if updates.timeout is not None:
            update_data['timeout'] = updates.timeout
        
        if not update_data:
            raise HTTPException(status_code=400, detail="No fields to update")
        
        db.update_script(
            script_id=script_id,
            script_path=update_data.get('script_path', script['script_path']),
            description=update_data.get('description', script.get('description')),
        )
        
        logger.info(f"Script updated: {script_id} by {user.get('token_name', 'unknown')}")
        
        updated_script = db.get_script(script_id)
        return {
            "message": "Script updated successfully",
            "script": updated_script
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating script {script_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to update script: {str(e)}")


@router.delete("/{script_id}")
async def delete_script(
    script_id: str,
    user: dict = Depends(require_admin)
):
    """
    Delete script registration (does not delete the file)
    
    **REQUIRES ADMIN TOKEN**
    """
    db = get_db()
    
    script = db.get_script(script_id)
    if not script:
        raise HTTPException(status_code=404, detail=f"Script '{script_id}' not found")
    
    try:
        # Check if script is used by any workflows
        workflows = db.list_workflows(limit=None)
        workflows_using_script = [w for w in workflows if w.get('script_id') == script_id]
        
        if workflows_using_script:
            raise HTTPException(
                status_code=409,
                detail=f"Cannot delete script: used by {len(workflows_using_script)} workflow(s)"
            )
        
        db.delete_script(script_id)
        
        logger.info(f"Script deleted: {script_id} by {user.get('token_name', 'unknown')}")
        
        return {
            "message": "Script registration deleted successfully",
            "script_id": script_id,
            "note": "Script file on filesystem was not deleted"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting script {script_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to delete script: {str(e)}")


@router.get("/{script_id}/workflows")
async def get_script_workflows(
    script_id: str,
    user: dict = Depends(verify_token)
):
    """
    Get all workflows that use this script
    
    Anyone authenticated can view
    """
    db = get_db()
    
    script = db.get_script(script_id)
    if not script:
        raise HTTPException(status_code=404, detail=f"Script '{script_id}' not found")
    
    try:
        all_workflows = db.list_workflows(limit=None)
        script_workflows = [w for w in all_workflows if w.get('script_id') == script_id]
        
        logger.debug(f"Found {len(script_workflows)} workflows using script: {script_id}")
        
        return {
            "script_id": script_id,
            "workflows": script_workflows,
            "count": len(script_workflows)
        }
        
    except Exception as e:
        logger.error(f"Error getting workflows for script {script_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
