import React, { useState, useEffect, useCallback } from 'react';
import { RefreshCw } from 'lucide-react';

const Dashboard = () => {
  const [token, setToken] = useState(localStorage.getItem('api_token') || '');
  const [workflows, setWorkflows] = useState([]);
  const [agents, setAgents] = useState([]);
  const [selectedAgents, setSelectedAgents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [logs, setLogs] = useState([]);

  const addLog = useCallback((message, type = 'info') => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, { message, type, timestamp }].slice(-50));
  }, []);

  const apiCall = useCallback(async (endpoint, options = {}) => {
    try {
      const response = await fetch(`/api${endpoint}`, {
        ...options,
        headers: {
          'Content-Type': 'application/json',
          'X-ADMIN-TOKEN': token,
          ...options.headers,
        },
      });

      if (!response.ok) {
        const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
        throw new Error(error.detail || `HTTP ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      addLog(`API Error: ${error.message}`, 'error');
      throw error;
    }
  }, [token, addLog]);

  const loadData = useCallback(async () => {
    if (!token) {
      addLog('Please enter an API token', 'warn');
      return;
    }

    setLoading(true);
    addLog('Loading data...');

    try {
      const [workflowsData, agentsData] = await Promise.all([
        apiCall('/workflows').catch(() => ({ workflows: [], count: 0 })),
        apiCall('/agents/').catch(() => ({ agents: [], count: 0 })),
      ]);

      setWorkflows(Array.isArray(workflowsData) ? workflowsData : (workflowsData.workflows || []));
      setAgents(Array.isArray(agentsData) ? agentsData : (agentsData.agents || []));

      addLog('Data loaded successfully', 'success');
    } catch (error) {
      addLog(`Failed to load data: ${error.message}`, 'error');
    } finally {
      setLoading(false);
    }
  }, [token, apiCall, addLog]);

  useEffect(() => {
    if (token) {
      loadData();
      const interval = setInterval(loadData, 30000);
      return () => clearInterval(interval);
    }
  }, [token, loadData]);

  const saveToken = () => {
    localStorage.setItem('api_token', token);
    addLog('Token saved', 'success');
    loadData();
  };

  const createWorkflow = async () => {
    const scriptId = document.getElementById('wfScriptId')?.value.trim();
    const requestor = document.getElementById('wfRequestor')?.value.trim();
    const reason = document.getElementById('wfReason')?.value.trim();

    if (!scriptId || !requestor || !reason) {
      addLog('Please fill in all workflow fields', 'error');
      return;
    }

    if (selectedAgents.length === 0) {
      addLog('Please select at least one target agent', 'error');
      return;
    }

    try {
      await apiCall('/workflows', {
        method: 'POST',
        body: JSON.stringify({
          script_id: scriptId,
          targets: selectedAgents,
          requestor,
          reason,
          required_approval_levels: 1,
          ttl_minutes: 60,
        }),
      });

      addLog('Workflow created successfully', 'success');
      document.getElementById('wfScriptId').value = '';
      document.getElementById('wfReason').value = '';
      setSelectedAgents([]);
      loadData();
    } catch (error) {
      addLog(`Failed to create workflow: ${error.message}`, 'error');
    }
  };

  const approveWorkflow = async (workflowId) => {
    try {
      await apiCall(`/workflows/${workflowId}/approve`, {
        method: 'POST',
        body: JSON.stringify({ approver: 'admin', note: 'Approved from dashboard' }),
      });
      addLog(`Workflow ${workflowId} approved`, 'success');
      loadData();
    } catch (error) {
      addLog(`Failed to approve: ${error.message}`, 'error');
    }
  };

  const executeWorkflow = async (workflowId) => {
    try {
      await apiCall(`/workflows/${workflowId}/execute`, { method: 'POST' });
      addLog(`Workflow ${workflowId} execution started`, 'success');
      loadData();
    } catch (error) {
      addLog(`Failed to execute: ${error.message}`, 'error');
    }
  };

  const registerAgent = async () => {
    const agentName = document.getElementById('agentName')?.value.trim();
    const host = document.getElementById('agentHost')?.value.trim();
    const portStr = document.getElementById('agentPort')?.value.trim();

    if (!agentName || !host || !portStr) {
      addLog('Please fill in all agent fields', 'error');
      return;
    }

    const port = parseInt(portStr, 10);
    if (isNaN(port) || port < 1 || port > 65535) {
      addLog('Port must be a number between 1 and 65535', 'error');
      return;
    }

    try {
      await apiCall('/agents/register', {
        method: 'POST',
        body: JSON.stringify({
          agent_name: agentName,
          host,
          port,
        }),
      });

      addLog(`Agent ${agentName} registered successfully`, 'success');
      document.getElementById('agentName').value = '';
      document.getElementById('agentHost').value = '';
      document.getElementById('agentPort').value = '8001';
      loadData();
    } catch (error) {
      addLog(`Failed to register agent: ${error.message}`, 'error');
    }
  };

  const formatDate = (dateStr) => {
    if (!dateStr) return 'Never';
    const date = new Date(dateStr);
    const now = new Date();
    const diffMins = Math.floor((now - date) / 60000);
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    return date.toLocaleDateString();
  };

  const kpiTotal = workflows.length;
  const kpiPending = workflows.filter(w => w.status === 'pending').length;
  const kpiApproved = workflows.filter(w => w.status === 'approved').length;

  return (
    <div style={{
      minHeight: '100vh',
      background: 'radial-gradient(circle at top, #1d243b 0%, #020617 45%, #020617 100%)',
      color: '#e5e7eb',
      fontFamily: 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
      display: 'flex',
      justifyContent: 'center',
    }}>
      <div style={{ width: '100%', maxWidth: '1240px', padding: '24px 20px 32px' }}>
        {/* Header */}
        <header style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '18px', gap: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{
              width: '38px',
              height: '38px',
              borderRadius: '999px',
              background: 'radial-gradient(circle at 25% 25%, #38bdf8, #0f172a 60%, #020617 100%)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 0 0 1px rgba(56,189,248,0.6), 0 14px 30px rgba(8,47,73,0.8)',
            }}>
              <span style={{ fontSize: '13px', fontWeight: 700, letterSpacing: '0.14em', color: 'white' }}>ORC</span>
            </div>
            <div>
              <h1 style={{ fontSize: '22px', fontWeight: 650, margin: 0, display: 'flex', gap: '8px', alignItems: 'baseline' }}>
                Orchestration
                <span style={{
                  fontSize: '11px',
                  fontWeight: 500,
                  padding: '3px 9px',
                  borderRadius: '999px',
                  background: 'rgba(15,23,42,0.8)',
                  border: '1px solid rgba(148,163,184,0.3)',
                  color: '#9ca3af',
                  textTransform: 'uppercase',
                  letterSpacing: '0.16em',
                }}>Control Panel</span>
              </h1>
              <div style={{ fontSize: '13px', color: '#9ca3af' }}>Secure workflow approvals & remote agent execution.</div>
            </div>
          </div>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '7px 10px',
            borderRadius: '999px',
            background: 'radial-gradient(circle at 0 0, rgba(56,189,248,0.35), transparent 55%)',
            border: '1px solid rgba(148,163,184,0.5)',
            boxShadow: '0 10px 30px rgba(15,23,42,0.6)',
          }}>
            <span style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.16em', color: '#9ca3af' }}>Admin Token</span>
            <input
              type="password"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder="Paste X-ADMIN-TOKEN value"
              style={{
                border: 'none',
                outline: 'none',
                background: 'rgba(15,23,42,0.95)',
                color: '#e5e7eb',
                fontSize: '12px',
                padding: '4px 10px',
                borderRadius: '999px',
                minWidth: '160px',
              }}
            />
            <button
              onClick={saveToken}
              style={{
                background: 'linear-gradient(135deg, #38bdf8, #0ea5e9)',
                color: '#0b1120',
                border: 'none',
                borderRadius: '999px',
                padding: '6px 14px',
                fontSize: '12px',
                fontWeight: 500,
                cursor: 'pointer',
                boxShadow: '0 14px 35px rgba(8,47,73,0.85)',
              }}
            >Save Token</button>
            <button
              onClick={loadData}
              disabled={loading}
              style={{
                background: 'rgba(15,23,42,0.9)',
                color: '#e5e7eb',
                border: '1px solid rgba(148,163,184,0.6)',
                borderRadius: '999px',
                padding: '6px 10px',
                cursor: 'pointer',
                opacity: loading ? 0.5 : 1,
              }}
            >
              <RefreshCw size={16} style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }} />
            </button>
          </div>
        </header>

        {/* Main Content */}
        <main style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 2.3fr) minmax(0, 1.6fr)', gap: '18px' }}>
          {/* Workflows Section */}
          <section style={{
            borderRadius: '18px',
            background: 'radial-gradient(circle at 0 0, rgba(148,163,184,0.09), transparent 55%), #020617',
            border: '1px solid rgba(148,163,184,0.3)',
            boxShadow: '0 18px 45px rgba(15,23,42,0.75)',
            padding: '14px',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
              <div>
                <div style={{ fontSize: '14px', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: '#9ca3af' }}>Workflows</div>
                <div style={{ fontSize: '12px', color: '#9ca3af', marginTop: '4px' }}>Create, review and execute approved runs.</div>
              </div>
              <button onClick={loadData} style={{
                background: 'rgba(15,23,42,0.9)',
                color: '#e5e7eb',
                border: '1px solid rgba(148,163,184,0.6)',
                borderRadius: '999px',
                padding: '6px 14px',
                fontSize: '12px',
                cursor: 'pointer',
              }}>Refresh</button>
            </div>

            {/* KPIs */}
            <div style={{ display: 'flex', gap: '8px', marginBottom: '12px' }}>
              <div style={{ flex: 1, borderRadius: '12px', background: 'rgba(15,23,42,0.9)', border: '1px solid rgba(148,163,184,0.3)', padding: '6px 9px' }}>
                <div style={{ fontSize: '11px', color: '#9ca3af', textTransform: 'uppercase' }}>Total</div>
                <div style={{ fontSize: '15px', fontWeight: 600 }}>{kpiTotal}</div>
              </div>
              <div style={{ flex: 1, borderRadius: '12px', background: 'rgba(15,23,42,0.9)', border: '1px solid rgba(148,163,184,0.3)', padding: '6px 9px' }}>
                <div style={{ fontSize: '11px', color: '#9ca3af', textTransform: 'uppercase' }}>Pending</div>
                <div style={{ fontSize: '15px', fontWeight: 600 }}>{kpiPending}</div>
              </div>
              <div style={{ flex: 1, borderRadius: '12px', background: 'rgba(15,23,42,0.9)', border: '1px solid rgba(148,163,184,0.3)', padding: '6px 9px' }}>
                <div style={{ fontSize: '11px', color: '#9ca3af', textTransform: 'uppercase' }}>Approved</div>
                <div style={{ fontSize: '15px', fontWeight: 600 }}>{kpiApproved}</div>
              </div>
            </div>

            {/* Workflows Table */}
            <div style={{ maxHeight: '260px', overflow: 'auto', borderRadius: '10px', border: '1px solid rgba(15,23,42,1)', marginBottom: '16px' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                <thead>
                  <tr style={{ background: 'rgba(15,23,42,0.9)' }}>
                    <th style={{ padding: '6px 8px', textAlign: 'left', fontSize: '11px', textTransform: 'uppercase', color: '#9ca3af' }}>ID</th>
                    <th style={{ padding: '6px 8px', textAlign: 'left', fontSize: '11px', textTransform: 'uppercase', color: '#9ca3af' }}>Script</th>
                    <th style={{ padding: '6px 8px', textAlign: 'left', fontSize: '11px', textTransform: 'uppercase', color: '#9ca3af' }}>Status</th>
                    <th style={{ padding: '6px 8px', textAlign: 'left', fontSize: '11px', textTransform: 'uppercase', color: '#9ca3af' }}>Created</th>
                    <th style={{ padding: '6px 8px', textAlign: 'right', fontSize: '11px', textTransform: 'uppercase', color: '#9ca3af' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {workflows.length === 0 ? (
                    <tr><td colSpan="5" style={{ textAlign: 'center', padding: '20px', color: '#9ca3af' }}>No workflows found</td></tr>
                  ) : (
                    workflows.map((wf, idx) => (
                      <tr key={wf.workflow_id} style={{ background: idx % 2 === 0 ? 'rgba(15,23,42,0.7)' : 'rgba(15,23,42,0.9)' }}>
                        <td style={{ padding: '6px 8px' }}>{wf.workflow_id}</td>
                        <td style={{ padding: '6px 8px' }}>
                          <span style={{
                            fontFamily: 'monospace',
                            fontSize: '11px',
                            padding: '2px 6px',
                            borderRadius: '6px',
                            background: 'rgba(15,23,42,0.8)',
                            border: '1px solid rgba(148,163,184,0.5)',
                          }}>{wf.script_id}</span>
                        </td>
                        <td style={{ padding: '6px 8px' }}>
                          <span style={{
                            padding: '2px 8px',
                            borderRadius: '999px',
                            fontSize: '11px',
                            textTransform: 'uppercase',
                            ...(wf.status === 'pending' ? { background: 'rgba(251,191,36,0.1)', color: '#fde68a', border: '1px solid rgba(251,191,36,0.6)' } :
                               wf.status === 'approved' ? { background: 'rgba(52,211,153,0.16)', color: '#6ee7b7', border: '1px solid rgba(52,211,153,0.7)' } :
                               { background: 'rgba(248,113,113,0.12)', color: '#fecaca', border: '1px solid rgba(248,113,113,0.7)' })
                          }}>{wf.status}</span>
                        </td>
                        <td style={{ padding: '6px 8px', fontSize: '11px', color: '#9ca3af' }}>{formatDate(wf.created_at)}</td>
                        <td style={{ padding: '6px 8px', textAlign: 'right' }}>
                          {wf.status === 'pending' && (
                            <button onClick={() => approveWorkflow(wf.workflow_id)} style={{
                              background: 'rgba(15,23,42,0.9)',
                              color: '#e5e7eb',
                              border: '1px solid rgba(148,163,184,0.6)',
                              borderRadius: '999px',
                              padding: '4px 8px',
                              fontSize: '10px',
                              cursor: 'pointer',
                            }}>Approve</button>
                          )}
                          {wf.status === 'approved' && (
                            <button onClick={() => executeWorkflow(wf.workflow_id)} style={{
                              background: 'linear-gradient(135deg, #38bdf8, #0ea5e9)',
                              color: '#0b1120',
                              border: 'none',
                              borderRadius: '999px',
                              padding: '4px 8px',
                              fontSize: '10px',
                              cursor: 'pointer',
                            }}>Execute</button>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {/* Create Workflow Form */}
            <div style={{ borderTop: '1px solid rgba(15,23,42,0.95)', paddingTop: '16px' }}>
              <div style={{ fontSize: '14px', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: '#9ca3af', marginBottom: '8px' }}>New Workflow</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '8px', marginBottom: '8px' }}>
                <div>
                  <div style={{ fontSize: '11px', textTransform: 'uppercase', color: '#9ca3af', marginBottom: '3px' }}>Script ID</div>
                  <input id="wfScriptId" placeholder="backup_db_prod" style={{
                    width: '100%',
                    padding: '7px 9px',
                    borderRadius: '10px',
                    border: '1px solid rgba(148,163,184,0.4)',
                    background: 'rgba(15,23,42,0.95)',
                    color: '#e5e7eb',
                    fontSize: '12px',
                  }} />
                </div>
                <div>
                  <div style={{ fontSize: '11px', textTransform: 'uppercase', color: '#9ca3af', marginBottom: '3px' }}>Requestor</div>
                  <input id="wfRequestor" defaultValue="admin" style={{
                    width: '100%',
                    padding: '7px 9px',
                    borderRadius: '10px',
                    border: '1px solid rgba(148,163,184,0.4)',
                    background: 'rgba(15,23,42,0.95)',
                    color: '#e5e7eb',
                    fontSize: '12px',
                  }} />
                </div>
                <div style={{ gridColumn: '1 / -1' }}>
                  <div style={{ fontSize: '11px', textTransform: 'uppercase', color: '#9ca3af', marginBottom: '3px' }}>
                    Target Agents ({selectedAgents.length} selected)
                  </div>
                  <div style={{
                    maxHeight: '140px',
                    overflow: 'auto',
                    border: '1px solid rgba(148,163,184,0.4)',
                    borderRadius: '10px',
                    background: 'rgba(15,23,42,0.95)',
                    padding: '8px',
                  }}>
                    {agents.length === 0 ? (
                      <div style={{ color: '#9ca3af', fontSize: '11px', padding: '4px', textAlign: 'center' }}>
                        No agents registered. Register an agent first →
                      </div>
                    ) : (
                      agents.map((agent) => (
                        <label key={agent.agent_name} style={{
                          display: 'flex',
                          alignItems: 'center',
                          padding: '5px 6px',
                          cursor: 'pointer',
                          borderRadius: '6px',
                          transition: 'background 0.2s',
                        }}
                        onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(56,189,248,0.1)'}
                        onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                        >
                          <input
                            type="checkbox"
                            checked={selectedAgents.includes(agent.agent_name)}
                            onChange={(e) => {
                              if (e.target.checked) {
                                setSelectedAgents([...selectedAgents, agent.agent_name]);
                              } else {
                                setSelectedAgents(selectedAgents.filter(a => a !== agent.agent_name));
                              }
                            }}
                            style={{
                              marginRight: '8px',
                              cursor: 'pointer',
                              accentColor: '#38bdf8',
                            }}
                          />
                          <span style={{ fontSize: '12px', color: '#e5e7eb', flex: 1 }}>
                            {agent.agent_name}
                          </span>
                          <span style={{
                            fontSize: '10px',
                            padding: '2px 6px',
                            borderRadius: '999px',
                            background: agent.status === 'online' ? 'rgba(34,197,94,0.2)' : 'rgba(239,68,68,0.2)',
                            color: agent.status === 'online' ? '#4ade80' : '#f87171',
                          }}>
                            {agent.status}
                          </span>
                        </label>
                      ))
                    )}
                  </div>
                  <div style={{ fontSize: '10px', color: '#9ca3af', marginTop: '4px' }}>
                    Select one or more agents to execute this workflow
                  </div>
                </div>
                <div style={{ gridColumn: '1 / -1' }}>
                  <div style={{ fontSize: '11px', textTransform: 'uppercase', color: '#9ca3af', marginBottom: '3px' }}>Reason</div>
                  <input id="wfReason" placeholder="Describe why this run is needed" style={{
                    width: '100%',
                    padding: '7px 9px',
                    borderRadius: '10px',
                    border: '1px solid rgba(148,163,184,0.4)',
                    background: 'rgba(15,23,42,0.95)',
                    color: '#e5e7eb',
                    fontSize: '12px',
                  }} />
                </div>
              </div>
              <button onClick={createWorkflow} style={{
                background: 'linear-gradient(135deg, #38bdf8, #0ea5e9)',
                color: '#0b1120',
                border: 'none',
                borderRadius: '999px',
                padding: '6px 14px',
                fontSize: '12px',
                fontWeight: 500,
                cursor: 'pointer',
                boxShadow: '0 14px 35px rgba(8,47,73,0.85)',
              }}>Create Workflow</button>
            </div>
          </section>

          {/* Agents Section */}
          <section style={{
            borderRadius: '18px',
            background: 'radial-gradient(circle at 0 0, rgba(148,163,184,0.09), transparent 55%), #020617',
            border: '1px solid rgba(148,163,184,0.3)',
            boxShadow: '0 18px 45px rgba(15,23,42,0.75)',
            padding: '14px',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
              <div>
                <div style={{ fontSize: '14px', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: '#9ca3af' }}>Agents</div>
                <div style={{ fontSize: '12px', color: '#9ca3af', marginTop: '4px' }}>Online agents able to execute allowed scripts.</div>
              </div>
              <button onClick={loadData} style={{
                background: 'rgba(15,23,42,0.9)',
                color: '#e5e7eb',
                border: '1px solid rgba(148,163,184,0.6)',
                borderRadius: '999px',
                padding: '6px 14px',
                fontSize: '12px',
                cursor: 'pointer',
              }}>Refresh</button>
            </div>

            {/* Agents Table */}
            <div style={{ maxHeight: '180px', overflow: 'auto', borderRadius: '10px', border: '1px solid rgba(15,23,42,1)', marginBottom: '10px' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                <thead>
                  <tr style={{ background: 'rgba(15,23,42,0.9)' }}>
                    <th style={{ padding: '6px 8px', textAlign: 'left', fontSize: '11px', textTransform: 'uppercase', color: '#9ca3af' }}>Name</th>
                    <th style={{ padding: '6px 8px', textAlign: 'left', fontSize: '11px', textTransform: 'uppercase', color: '#9ca3af' }}>Host</th>
                    <th style={{ padding: '6px 8px', textAlign: 'left', fontSize: '11px', textTransform: 'uppercase', color: '#9ca3af' }}>Port</th>
                    <th style={{ padding: '6px 8px', textAlign: 'left', fontSize: '11px', textTransform: 'uppercase', color: '#9ca3af' }}>Status</th>
                    <th style={{ padding: '6px 8px', textAlign: 'left', fontSize: '11px', textTransform: 'uppercase', color: '#9ca3af' }}>Last Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {agents.length === 0 ? (
                    <tr><td colSpan="5" style={{ textAlign: 'center', padding: '20px', color: '#9ca3af' }}>No agents registered</td></tr>
                  ) : (
                    agents.map((agent, idx) => (
                      <tr key={agent.agent_name} style={{ background: idx % 2 === 0 ? 'rgba(15,23,42,0.7)' : 'rgba(15,23,42,0.9)' }}>
                        <td style={{ padding: '6px 8px' }}>{agent.agent_name}</td>
                        <td style={{ padding: '6px 8px' }}>{agent.host}</td>
                        <td style={{ padding: '6px 8px' }}>{agent.port}</td>
                        <td style={{ padding: '6px 8px' }}>
                          <span style={{
                            padding: '2px 8px',
                            borderRadius: '999px',
                            fontSize: '11px',
                            textTransform: 'uppercase',
                            ...(agent.status === 'online' ? { background: 'rgba(52,211,153,0.16)', color: '#6ee7b7', border: '1px solid rgba(52,211,153,0.7)' } :
                               { background: 'rgba(148,163,184,0.1)', color: '#cbd5e1', border: '1px solid rgba(148,163,184,0.5)' })
                          }}>{agent.status}</span>
                        </td>
                        <td style={{ padding: '6px 8px', fontSize: '11px', color: '#9ca3af' }}>{formatDate(agent.last_seen)}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {/* Register Agent Form */}
            <div style={{ borderTop: '1px solid rgba(15,23,42,0.95)', paddingTop: '16px', marginBottom: '16px' }}>
              <div style={{ fontSize: '14px', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: '#9ca3af', marginBottom: '8px' }}>Register Agent</div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '8px', marginBottom: '8px' }}>
                <div>
                  <div style={{ fontSize: '11px', textTransform: 'uppercase', color: '#9ca3af', marginBottom: '3px' }}>Agent Name</div>
                  <input id="agentName" placeholder="server1" style={{
                    width: '100%',
                    padding: '7px 9px',
                    borderRadius: '10px',
                    border: '1px solid rgba(148,163,184,0.4)',
                    background: 'rgba(15,23,42,0.95)',
                    color: '#e5e7eb',
                    fontSize: '12px',
                  }} />
                </div>
                <div>
                  <div style={{ fontSize: '11px', textTransform: 'uppercase', color: '#9ca3af', marginBottom: '3px' }}>Host</div>
                  <input id="agentHost" placeholder="192.168.1.100" style={{
                    width: '100%',
                    padding: '7px 9px',
                    borderRadius: '10px',
                    border: '1px solid rgba(148,163,184,0.4)',
                    background: 'rgba(15,23,42,0.95)',
                    color: '#e5e7eb',
                    fontSize: '12px',
                  }} />
                </div>
                <div>
                  <div style={{ fontSize: '11px', textTransform: 'uppercase', color: '#9ca3af', marginBottom: '3px' }}>Port</div>
                  <input id="agentPort" type="number" defaultValue="8001" style={{
                    width: '100%',
                    padding: '7px 9px',
                    borderRadius: '10px',
                    border: '1px solid rgba(148,163,184,0.4)',
                    background: 'rgba(15,23,42,0.95)',
                    color: '#e5e7eb',
                    fontSize: '12px',
                  }} />
                </div>
              </div>
              <button onClick={registerAgent} style={{
                background: 'linear-gradient(135deg, #38bdf8, #0ea5e9)',
                color: '#0b1120',
                border: 'none',
                borderRadius: '999px',
                padding: '6px 14px',
                fontSize: '12px',
                fontWeight: 500,
                cursor: 'pointer',
                boxShadow: '0 14px 35px rgba(8,47,73,0.85)',
              }}>Register Agent</button>
            </div>

            {/* Activity Log */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                <div style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.14em', color: '#9ca3af' }}>Activity Log</div>
                <button onClick={() => setLogs([])} style={{
                  background: 'transparent',
                  color: '#9ca3af',
                  border: '1px solid rgba(148,163,184,0.3)',
                  borderRadius: '999px',
                  padding: '4px 10px',
                  fontSize: '11px',
                  cursor: 'pointer',
                }}>Clear</button>
              </div>
              <textarea
                readOnly
                value={logs.map(log => `${log.timestamp} [${log.type.toUpperCase()}] ${log.message}`).join('\n')}
                style={{
                  width: '100%',
                  minHeight: '120px',
                  resize: 'vertical',
                  borderRadius: '12px',
                  border: '1px solid rgba(15,23,42,1)',
                  background: 'radial-gradient(circle at top left, rgba(15,118,110,0.25), #020617 40%)',
                  color: '#e5e7eb',
                  fontFamily: 'monospace',
                  fontSize: '12px',
                  padding: '9px 10px',
                  boxShadow: '0 16px 35px rgba(15,23,42,0.9)',
                }}
              />
            </div>
          </section>
        </main>

        <style>{`
          @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
          }
        `}</style>
      </div>
    </div>
  );
};

export default Dashboard;
