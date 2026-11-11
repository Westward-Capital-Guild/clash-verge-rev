import React, { useState } from 'react'
import { createRoot } from 'react-dom/client'

import { WorkspaceView } from '../../src/components/workspace/workspace-view'
import type { WorkspaceClient } from '../../src/services/workspace'

const { endpoint, capability } = (
  window as unknown as {
    __WORKSPACE_SMOKE__: { endpoint: string; capability: string }
  }
).__WORKSPACE_SMOKE__

const client: WorkspaceClient = {
  async remote(action, hostId, workspaceId) {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${capability}`,
      },
      body: JSON.stringify({ action: `remote-${action}`, hostId, workspaceId }),
    })
    if (!response.ok) throw new Error('Smoke operation failed')
    return response.json()
  },
  async run(action) {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${capability}`,
      },
      body: JSON.stringify({ action }),
    })
    if (!response.ok) throw new Error('Smoke operation failed')
    return response.json()
  },
}

export const SmokeWorkspace = () => {
  const [page, setPage] = useState<'workbench' | 'development'>('workbench')
  return (
    <>
      <nav
        aria-label="Smoke 页面"
        style={{ display: 'flex', gap: 16, padding: 16 }}
      >
        {(['workbench', 'development'] as const).map((value) => (
          <button
            key={value}
            type="button"
            aria-pressed={page === value}
            style={{ minHeight: 44, fontSize: 14 }}
            onClick={() => setPage(value)}
          >
            {value === 'workbench' ? '工作台' : '开发环境'}
          </button>
        ))}
      </nav>
      <WorkspaceView key={page} client={client} page={page} />
    </>
  )
}

createRoot(document.getElementById('root')!).render(<SmokeWorkspace />)
