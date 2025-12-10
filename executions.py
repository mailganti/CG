# controller/routes/executions.py - Execution logs endpoint

"""
API endpoints for viewing execution logs
Add this to your routes or create a new file
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import Optional
import logging
import os

from controller.deps import verify_token
from controller.db.db import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/executions", tags=["executions"])


@router.get("/{execution_id}/logs")
async def get_execution_logs(
    execution_id: int,
    tail: Optional[int] = None,  # Last N lines
    user: dict = Depends(verify_token)
):
    """
    Get logs for a specific execution
    
    Parameters:
    - execution_id: The execution ID
    - tail: Optional - return only last N lines
    """
    db = get_db()
    
    # Get execution details
    execution = db.get_execution(execution_id)
    
    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")
    
    # Get log file path from execution or construct it
    log_file = execution.get('log_file')
    
    if not log_file:
        # Construct log file path based on execution ID
        # Adjust this path based on your setup
        log_dir = os.getenv('LOG_DIR', 'logs')
        log_file = os.path.join(log_dir, f'execution_{execution_id}.log')
    
    # Check if log file exists
    if not os.path.exists(log_file):
        # Return execution info but indicate no logs yet
        return {
            "execution_id": execution_id,
            "status": execution.get('status'),
            "log_file": log_file,
            "logs": [],
            "message": "Log file not yet created or execution has no logs"
        }
    
    try:
        # Read log file
        with open(log_file, 'r') as f:
            if tail:
                # Read last N lines
                lines = f.readlines()
                logs = lines[-tail:] if len(lines) > tail else lines
            else:
                # Read all lines
                logs = f.readlines()
        
        # Clean up lines (remove trailing newlines)
        logs = [line.rstrip('\n') for line in logs]
        
        return {
            "execution_id": execution_id,
            "status": execution.get('status'),
            "workflow_id": execution.get('workflow_id'),
            "started_at": execution.get('started_at'),
            "completed_at": execution.get('completed_at'),
            "log_file": log_file,
            "logs": logs,
            "total_lines": len(logs)
        }
        
    except Exception as e:
        logger.error(f"Failed to read log file {log_file}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to read log file: {str(e)}"
        )


@router.get("/{execution_id}/logs/stream")
async def stream_execution_logs(
    execution_id: int,
    user: dict = Depends(verify_token)
):
    """
    Stream logs in real-time for running execution
    
    This can be enhanced to use Server-Sent Events (SSE)
    for real-time streaming
    """
    db = get_db()
    
    execution = db.get_execution(execution_id)
    
    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")
    
    # For now, just return latest logs
    # Can be enhanced with SSE or WebSocket for real-time streaming
    return await get_execution_logs(execution_id, tail=100, user=user)


@router.get("/{execution_id}")
async def get_execution_details(
    execution_id: int,
    user: dict = Depends(verify_token)
):
    """
    Get full execution details
    """
    db = get_db()
    
    execution = db.get_execution(execution_id)
    
    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")
    
    return execution


#from controller.routes.executions import router as executions_router
#app.include_router(executions_router, prefix="/api")
