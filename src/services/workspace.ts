import { workspaceAction } from './cmds'
import { mutate } from './mutate'
import type { WorkspaceAction, WorkspaceStatus } from './workspace-contract'

export type { WorkspaceAction, WorkspaceStatus } from './workspace-contract'

export interface WorkspaceClient {
  run: (action: WorkspaceAction) => Promise<WorkspaceStatus>
}

export const workspaceClient: WorkspaceClient = {
  async run(action) {
    const command = () => workspaceAction(action)
    if (action === 'status') return command()
    const result = await mutate(command, {
      id: 'workspace',
      errorNotice: false,
      revalidate: [['getVergeConfig'], ['getProfiles']],
    })
    return result.value
  },
}
