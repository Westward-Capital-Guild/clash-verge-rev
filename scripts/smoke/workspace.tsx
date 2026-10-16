import React from 'react'
import { createRoot } from 'react-dom/client'

import { WorkspaceView } from '../../src/components/workspace/workspace-view'
import type { WorkspaceClient } from '../../src/services/workspace'

const { endpoint, capability } = (
  window as unknown as {
    __WORKSPACE_SMOKE__: { endpoint: string; capability: string }
  }
).__WORKSPACE_SMOKE__

const client: WorkspaceClient = {
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

createRoot(document.getElementById('root')!).render(
  <WorkspaceView client={client} />,
)
