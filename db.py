# controller/db/db.py
"""
Database handler for orchestration system
Manages workflows, agents, tokens, scripts, and audit logs
"""

import sqlite3
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

# Database path relative to this file
# This file: controller/db/db.py
# Database: controller/orchestration.db
DB_FILE = Path(__file__).parent.parent / "orchestration.db"


class OrchestrationDB:
    """Database handler for orchestration system"""
    
    def __init__(self, db_file: Optional[str] = None):
        """
        Initialize database connection
        
        Args:
            db_file: Path to database file (optional, uses default if not provided)
        """
        if db_file is None:
            db_file = str(DB_FILE)
        
        # Verify database exists
        if not Path(db_file).exists():
            raise FileNotFoundError(f"Database not found: {db_file}")
        
        self.conn = sqlite3.connect(db_file, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        logger.info(f"Connected to database: {db_file}")
    
    def close(self):
        """Close database connection"""
        self.conn.close()
    
    # ==================== Workflow Methods ====================
    
    def list_workflows(self, limit: Optional[int] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List workflows with optional filtering
        
        Args:
            limit: Maximum number of workflows to return
            status: Filter by status (pending, approved, success, failed, etc.)
            
        Returns:
            List of workflow dicts
        """
        cursor = self.conn.cursor()
        
        # Build query with optional filters
        query = 'SELECT * FROM workflows'
        params = []
        
        if status:
            query += ' WHERE status = ?'
            params.append(status)
        
        query += ' ORDER BY created_at DESC'
        
        if limit:
            query += ' LIMIT ?'
            params.append(limit)
        
        cursor.execute(query, params)
        
        workflows = []
        for row in cursor.fetchall():
            workflow = dict(row)
            # Parse JSON fields
            if workflow.get('targets_json'):
                try:
                    workflow['targets'] = json.loads(workflow['targets_json'])
                except Exception:
                    workflow['targets'] = []
            if workflow.get('approvals_json'):
                try:
                    workflow['approvals'] = json.loads(workflow['approvals_json'])
                except Exception:
                    workflow['approvals'] = []
            workflows.append(workflow)
        
        return workflows
    
    def get_workflow(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        """Get specific workflow by ID"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM workflows WHERE workflow_id = ?', (workflow_id,))
        row = cursor.fetchone()
        
        if not row:
            return None
        
        workflow = dict(row)
        # Parse JSON fields
        if workflow.get('targets_json'):
            try:
                workflow['targets'] = json.loads(workflow['targets_json'])
            except Exception:
                workflow['targets'] = []
        if workflow.get('approvals_json'):
            try:
                workflow['approvals'] = json.loads(workflow['approvals_json'])
            except Exception:
                workflow['approvals'] = []
        
        return workflow
    
    def create_workflow(
        self,
        workflow_id: str,
        script_id: str,
        targets: List[str],
        requestor: str,
        required_levels: int = 1,
        notify_email: str = "",
        ttl_minutes: int = 60,
        reason: str = ""
    ) -> Dict[str, Any]:
        """Create a new workflow"""
        cursor = self.conn.cursor()
        
        # Convert lists to JSON strings
        targets_json = json.dumps(targets)
        approvals_json = json.dumps([])
        
        cursor.execute('''
            INSERT INTO workflows (
                workflow_id, script_id, targets_json, requestor,
                required_approval_levels, notify_email, ttl_minutes,
                status, created_at, approvals_json, reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            workflow_id, script_id, targets_json, requestor,
            required_levels, notify_email, ttl_minutes,
            'pending', datetime.utcnow().isoformat(), approvals_json, reason
        ))
        
        self.conn.commit()
        logger.info(f"Workflow created: {workflow_id}")
        
        return self.get_workflow(workflow_id)
    
    def update_workflow_status(self, workflow_id: str, status: str):
        """Update workflow status"""
        cursor = self.conn.cursor()
        cursor.execute('''
            UPDATE workflows SET status = ? WHERE workflow_id = ?
        ''', (status, workflow_id))
        self.conn.commit()
    
    def add_approval(self, workflow_id: str, approver: str, level: int = 1) -> bool:
        """Add approval to workflow"""
        workflow = self.get_workflow(workflow_id)
        if not workflow:
            return False
        
        approvals = workflow.get('approvals', [])
        
        # Check if already approved by this user
        for approval in approvals:
            if approval.get('approver') == approver:
                return False
        
        # Add new approval
        approvals.append({
            'approver': approver,
            'level': level,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        approvals_json = json.dumps(approvals)
        
        cursor = self.conn.cursor()
        cursor.execute('''
            UPDATE workflows SET approvals_json = ? WHERE workflow_id = ?
        ''', (approvals_json, workflow_id))
        
        self.conn.commit()
        return True
    
    def delete_workflow(self, workflow_id: str):
        """Delete a workflow"""
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM workflows WHERE workflow_id = ?', (workflow_id,))
        self.conn.commit()
    
    # ==================== Agent Methods ====================
    
    def list_agents(self, limit: Optional[int] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List agents with optional filtering
        
        Args:
            limit: Maximum number of agents to return
            status: Filter by status (online, offline)
            
        Returns:
            List of agent dicts
        """
        cursor = self.conn.cursor()
        
        # Build query with optional filters
        query = 'SELECT * FROM agents'
        params = []
        
        if status:
            query += ' WHERE status = ?'
            params.append(status)
        
        query += ' ORDER BY created_at DESC'
        
        if limit:
            query += ' LIMIT ?'
            params.append(limit)
        
        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]
    
    def get_agent(self, agent_name: str) -> Optional[Dict[str, Any]]:
        """Get specific agent by name"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM agents WHERE agent_name = ?', (agent_name,))
        row = cursor.fetchone()
        return dict(row) if row else None
    
    def get_agent_by_host_port(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """
        Get agent by host and port combination
        
        Args:
            host: Agent host (IP or hostname)
            port: Agent port
            
        Returns:
            Agent dict if found, None otherwise
        """
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT * FROM agents WHERE host = ? AND port = ?
        ''', (host, port))
        row = cursor.fetchone()
        return dict(row) if row else None

    def register_agent(
        self,
        agent_name: str,
        host: str,
        port: int,
        status: str = "online",
        ssl_enabled: bool = "true"
    ) -> Dict[str, Any]:
        """Register a new agent"""
        cursor = self.conn.cursor()
        cursor.execute('''
        INSERT INTO agents (agent_name, host, port, status, ssl_enabled, last_seen)
        VALUES (?, ?, ?, ?, ?, datetime('now'))
        ON CONFLICT(agent_name) DO UPDATE SET
            host = excluded.host,
            port = excluded.port,
            status = excluded.status,
            ssl_enabled = excluded.ssl_enabled,
            last_seen = datetime('now')
         ''', (agent_name, host, port, status, 1 if ssl_enabled else 0))
 
        self.conn.commit()
        return self.get_agent(agent_name)
    
    def update_agent_status(self, agent_name: str, status: str):
        """Update agent status"""
        cursor = self.conn.cursor()
        cursor.execute('''
            UPDATE agents SET status = ? WHERE agent_name = ?
        ''', (status, agent_name))
        self.conn.commit()
    
    def deregister_agent(self, agent_name: str):
        """Deregister an agent"""
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM agents WHERE agent_name = ?', (agent_name,))
        self.conn.commit()
    
    # ==================== Agent Heartbeat Methods ====================

    def update_agent_heartbeat(self, agent_name: str) -> bool:
        """Update the last_seen timestamp for an agent"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                UPDATE agents 
                SET last_seen = datetime('now'),
                    status = 'online'
                WHERE agent_name = ?
            ''', (agent_name,))
        
            self.conn.commit()
            
            # Check if update was successful
            return cursor.rowcount > 0

        except Exception as e:
            logger.error(f"Error updating heartbeat for {agent_name}: {e}")
            return False
    
    def get_agent_status(self, agent_name: str, timeout_seconds: int = 60) -> str:
        """
        Get real-time status of agent based on heartbeat
        
        Args:
            agent_name: Agent to check
            timeout_seconds: How long before considering offline (default: 60)
            
        Returns:
            'online' if heartbeat within timeout, 'offline' otherwise
        """
        from datetime import timedelta
        
        cursor = self.conn.cursor()
        
        cursor.execute('''
            SELECT last_seen, status
            FROM agents
            WHERE agent_name = ?
        ''', (agent_name,))
        
        row = cursor.fetchone()
        
        if not row:
            return 'unknown'
        
        last_seen_str = row['last_seen']
        
        if not last_seen_str:
            return 'offline'
        
        # Check if last_seen is within timeout
        try:
            last_seen = datetime.fromisoformat(last_seen_str)
            timeout_threshold = datetime.now() - timedelta(seconds=timeout_seconds)
            
            if last_seen > timeout_threshold:
                return 'online'
            else:
                return 'offline'
        except Exception:
            return 'offline'
    
    def list_agents_with_status(
        self,
        limit: Optional[int] = None,
        status: Optional[str] = None,
        timeout_seconds: int = 60
    ) -> List[Dict[str, Any]]:
        """
        List all agents with real-time status based on heartbeat
        
        Args:
            limit: Maximum number of agents to return
            status: Filter by status (after checking heartbeat)
            timeout_seconds: How long before considering offline (default: 60)
            
        Returns:
            List of agent dicts with accurate status
        """
        from datetime import timedelta
        
        cursor = self.conn.cursor()
        
        query = 'SELECT * FROM agents ORDER BY created_at DESC'
        
        if limit:
            query += f' LIMIT {limit}'
        
        cursor.execute(query)
        
        agents = []
        timeout_threshold = datetime.now() - timedelta(seconds=timeout_seconds)
        
        for row in cursor.fetchall():
            agent = dict(row)
            last_seen_str = agent.get('last_seen')
            
            # Determine real-time status based on heartbeat
            if not last_seen_str:
                agent['status'] = 'offline'
                agent['status_reason'] = 'Never seen'
            else:
                try:
                    last_seen = datetime.fromisoformat(last_seen_str)
                    seconds_ago = int((datetime.now() - last_seen).total_seconds())
                    
                    if last_seen > timeout_threshold:
                        agent['status'] = 'online'
                        agent['status_reason'] = f'Last seen {seconds_ago}s ago'
                    else:
                        agent['status'] = 'offline'
                        agent['status_reason'] = f'Last seen {seconds_ago}s ago'
                except Exception:
                    agent['status'] = 'offline'
                    agent['status_reason'] = 'Invalid timestamp'
            
            # Filter by status if requested
            if status and agent['status'] != status:
                continue
            
            agents.append(agent)
        
        return agents
    
    # ==================== Token Methods ====================
    
    def list_tokens(self, limit: Optional[int] = None, include_revoked: bool = True) -> List[Dict[str, Any]]:
        """
        List tokens with optional filtering
        
        Args:
            limit: Maximum number of tokens to return
            include_revoked: Include revoked tokens (default: True)
            
        Returns:
            List of token dicts (without token_value for security)
        """
        cursor = self.conn.cursor()
        
        # Build query with optional filters
        query = '''
            SELECT token_name, role, created_at, last_used, revoked, description
            FROM tokens
        '''
        params = []
        
        if not include_revoked:
            query += ' WHERE revoked = 0'
        
        query += ' ORDER BY created_at DESC'
        
        if limit:
            query += ' LIMIT ?'
            params.append(limit)
        
        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]
    
    def get_token(self, token_name: str) -> Optional[Dict[str, Any]]:
        """Get token by name"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM tokens WHERE token_name = ?', (token_name,))
        row = cursor.fetchone()
        return dict(row) if row else None
    
    def get_token_by_value(self, token_value: str) -> Optional[Dict[str, Any]]:
        """Get token by value (for authentication)"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM tokens WHERE token_value = ?', (token_value,))
        row = cursor.fetchone()
        return dict(row) if row else None
    
    def create_token(
        self,
        token_name: str,
        token_value: str,
        role: str = "viewer",
        description: str = ""
    ) -> Dict[str, Any]:
        """Create a new API token"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO tokens (token_name, token_value, role, description, created_at, revoked)
            VALUES (?, ?, ?, ?, ?, 0)
        ''', (token_name, token_value, role, description, datetime.utcnow().isoformat()))
        
        self.conn.commit()
        logger.info(f"Token created: {token_name} (role: {role})")
        
        return self.get_token(token_name)
    
    def revoke_token(self, token_name: str):
        """Revoke a token"""
        cursor = self.conn.cursor()
        cursor.execute('UPDATE tokens SET revoked = 1 WHERE token_name = ?', (token_name,))
        self.conn.commit()
    
    def restore_token(self, token_name: str):
        """Restore a revoked token"""
        cursor = self.conn.cursor()
        cursor.execute('UPDATE tokens SET revoked = 0 WHERE token_name = ?', (token_name,))
        self.conn.commit()
    
    def update_token_last_used(self, token_name: str):
        """Update token's last_used timestamp"""
        cursor = self.conn.cursor()
        cursor.execute('''
            UPDATE tokens SET last_used = ? WHERE token_name = ?
        ''', (datetime.utcnow().isoformat(), token_name))
        self.conn.commit()
    
    def delete_token(self, token_name: str):
        """Delete a token permanently"""
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM tokens WHERE token_name = ?', (token_name,))
        self.conn.commit()
    
    # ==================== Script Methods ====================

    def register_script(self, script_id: str, script_path: str, description: str = "") -> Dict[str, Any]:
        """
        Register a script that exists on the filesystem
        """
        cursor = self.conn.cursor()
    
        cursor.execute('''
        INSERT INTO scripts (script_id, script_path, description, created_at)
        VALUES (?, ?, ?, datetime('now'))
        ON CONFLICT(script_id) DO UPDATE SET
            script_path = excluded.script_path,
            description = excluded.description,
            updated_at = datetime('now')
        ''', (script_id, script_path, description))
    
        self.conn.commit()
    
        return self.get_script(script_id)

    def get_script(self, script_id: str) -> Optional[Dict[str, Any]]:
        """
        Get script by ID
        """
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM scripts WHERE script_id = ?', (script_id,))
        row = cursor.fetchone()
    
        return dict(row) if row else None

    def list_scripts(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        List all scripts
        """
        cursor = self.conn.cursor()
    
        query = 'SELECT * FROM scripts ORDER BY created_at DESC'
        params = []
    
        if limit:
            query += ' LIMIT ?'
            params.append(limit)
    
        cursor.execute(query, params)
        rows = cursor.fetchall()
    
        return [dict(row) for row in rows]

    def update_script(self, script_id: str, script_path: str, description: str) -> bool:
        """
        Update script details
        """
        cursor = self.conn.cursor()
    
        cursor.execute('''
        UPDATE scripts 
        SET script_path = ?, 
            description = ?,
            updated_at = datetime('now')
        WHERE script_id = ?
        ''', (script_path, description, script_id))
    
        self.conn.commit()
    
        return cursor.rowcount > 0

    def delete_script(self, script_id: str) -> bool:
        """
        Delete a script registration
        """
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM scripts WHERE script_id = ?', (script_id,))
        self.conn.commit()
    
        return cursor.rowcount > 0

    def get_script_by_path(self, script_path: str) -> Optional[Dict[str, Any]]:
        """
        Get script by filesystem path
        """
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM scripts WHERE script_path = ?', (script_path,))
        row = cursor.fetchone()
    
        return dict(row) if row else None

    # Optional: Migration helper methods

    def get_all_script_ids(self) -> List[str]:
        """Get all script IDs (useful for migration)"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT script_id FROM scripts ORDER BY script_id')
        return [row[0] for row in cursor.fetchall()]

    def script_exists(self, script_id: str) -> bool:
        """Check if script exists in database"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM scripts WHERE script_id = ?', (script_id,))
        return cursor.fetchone()[0] > 0
    
    # ==================== Audit Methods ====================
    
    def add_audit(self, workflow_id: str, action: str, user: str, note: str = ""):
        """Add audit log entry"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO audit_log (workflow_id, action, user, timestamp, note)
            VALUES (?, ?, ?, ?, ?)
        ''', (workflow_id, action, user, datetime.utcnow().isoformat(), note))
        self.conn.commit()
    
    def get_audit_logs(self, workflow_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get audit logs, optionally filtered by workflow"""
        cursor = self.conn.cursor()
        
        if workflow_id:
            cursor.execute('''
                SELECT * FROM audit_log
                WHERE workflow_id = ?
                ORDER BY timestamp DESC
            ''', (workflow_id,))
        else:
            cursor.execute('SELECT * FROM audit_log ORDER BY timestamp DESC')
        
        return [dict(row) for row in cursor.fetchall()]


# Singleton instance
_db_instance = None

def get_db() -> OrchestrationDB:
    """Get singleton database instance"""
    global _db_instance
    if _db_instance is None:
        _db_instance = OrchestrationDB(str(DB_FILE))
    return _db_instance


# Test connection
if __name__ == "__main__":
    try:
        db = get_db()
        print(f"[OK] Connected to database: {DB_FILE}")
        
        # Test queries
        agents = db.list_agents()
        print(f"[OK] Found {len(agents)} agents")
        
        workflows = db.list_workflows()
        print(f"[OK] Found {len(workflows)} workflows")
        
        tokens = db.list_tokens()
        print(f"[OK] Found {len(tokens)} tokens")
        
        scripts = db.list_scripts()
        print(f"[OK] Found {len(scripts)} scripts")
        
        print("\n[OK] Database connection test passed!")
        
    except Exception as e:
        print(f"[ERROR] Database test failed: {e}")
        import traceback
        traceback.print_exc()
