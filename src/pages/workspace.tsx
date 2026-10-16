import { useLocation, useNavigate } from 'react-router'

import { WorkspaceView } from '@/components/workspace/workspace-view'
import { workspaceClient } from '@/services/workspace'

export default function WorkspacePage() {
  const { pathname } = useLocation()
  const navigate = useNavigate()
  const page =
    pathname === '/development'
      ? 'development'
      : pathname === '/workspace-settings'
        ? 'settings'
        : 'workbench'
  return (
    <WorkspaceView
      client={workspaceClient}
      page={page}
      onDiagnostics={() => navigate('/settings')}
    />
  )
}
