import { workspaceAction, workspaceRemote } from './cmds'
import { mutate } from './mutate'
import type {
  WorkspaceAction,
  WorkspaceStatus,
  WorkspaceRemoteAction,
  WorkspaceRemoteStatus,
} from './workspace-contract'

export type {
  WorkspaceAction,
  WorkspaceStatus,
  WorkspaceRemoteAction,
  WorkspaceRemoteStatus,
} from './workspace-contract'

export interface WorkspaceClient {
  run: (action: WorkspaceAction) => Promise<WorkspaceStatus>
  remote?: (
    action: WorkspaceRemoteAction,
    hostId?: string,
    workspaceId?: string,
  ) => Promise<WorkspaceRemoteStatus>
}

export const workspaceClient: WorkspaceClient = {
  async remote(action, hostId, workspaceId) {
    const command = () => workspaceRemote(action, hostId, workspaceId)
    if (action === 'hosts') return command()
    const result = await mutate(command, {
      id: 'workspace-remote',
      errorNotice: false,
    })
    return result.value
  },
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

export function workspaceErrorMessage(failure: unknown): string {
  const code =
    failure && typeof failure === 'object' && 'code' in failure
      ? String(failure.code)
      : ''
  const messages: Record<string, string> = {
    SYSPROXY_RESTORE_FAILED:
      '本机代理设置未能完整恢复，请检查系统代理状态并联系公司支持。',
    SYSPROXY_SNAPSHOT_FAILED:
      '暂时无法读取原有代理状态，已停止接管，请稍后重试。',
    UNSUPPORTED_VERSION: '公司接入协议已更新，请联系公司支持更新客户端。',
    ENDPOINT_ORIGIN_MISMATCH:
      '公司接入信息未通过校验，已停止操作，请联系公司支持。',
    REDIRECT_FORBIDDEN: '公司接入地址返回了不受支持的跳转，请联系公司支持。',
    INVALID_SESSION: '登录已失效，请退出后重新登录。',
    SESSION_EXPIRED: '飞书登录已过期，请退出后重新登录。',
    MEMBER_NOT_REGISTERED: '你的工作区尚未开通，请联系管理员。',
    MEMBER_BINDING_MISMATCH: '账号与工作区绑定不一致，请联系管理员。',
    NETWORK_NOT_GRANTED: '当前账号没有公司网络权限，开发机权限可独立使用。',
    RESOURCE_NOT_READY: '个人网络配置尚未交付，请联系管理员。',
    RESOURCE_NOT_FOUND: '当前账号未获该资源授权，请刷新状态。',
    BINDING_CHANGED: '授权配置已更新，请刷新后重试。',
    WORKSPACE_UNAVAILABLE: '公司接入服务暂时不可用，请稍后重试。',
    OS_KEYRING_UNAVAILABLE: '系统凭据库暂不可用，请在本机确认访问权限后重试。',
    SIGN_IN_CANCELLED: '已取消登录，可以重新尝试。',
    SIGN_IN_TIMED_OUT: '登录等待已结束，请重新登录。',
    WORKSPACE_INVALID_PROFILE:
      '个人网络配置未通过校验，已保留原有配置，请联系管理员。',
    WORKSPACE_IMPORT_FAILED: '网络配置导入失败，已保留原有配置，请重试。',
    WORKSPACE_ACTIVATION_FAILED: '网络配置启用失败，原有配置仍保留，请重试。',
    SYSPROXY_PRIVILEGE_REQUIRED:
      '配置已导入，系统代理切换未完成，请确认本机系统授权。',
  }
  return messages[code] || '操作未完成，请稍后重试；仍然失败请联系公司支持。'
}
