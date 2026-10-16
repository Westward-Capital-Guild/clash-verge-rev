import { useCallback, useEffect, useRef, useState } from 'react'

import type {
  WorkspaceClient,
  WorkspaceRemoteAction,
  WorkspaceRemoteStatus,
} from '@/services/workspace'

const messages: Record<WorkspaceRemoteStatus['state'], string> = {
  unconfigured: '公司开发机自动接入服务尚未就绪，无需手动填写服务器信息。',
  signed_out: '登录后查看分配给你的开发机。',
  available: '请选择已授权的工作目录。远端继续使用已有的 Codex provider。',
  unassigned: '当前账号尚未分配开发机，不影响已授权的公司网络。',
  unavailable: '暂时无法取得开发机清单，请稍后重试。',
  not_authorized: '该开发机或目录已不在你的授权范围内，请刷新清单。',
  missing_key:
    '本机未找到与已登记指纹匹配的 SSH 密钥，请联系公司支持。无需上传私钥。',
  unverified_host: '开发机缺少已核验的主机密钥，请联系管理员补齐。',
  invalid_host: '开发机接入信息不完整，请联系管理员。',
  config_conflict:
    '已有 SSH 配置或主机密钥发生冲突，已保留原文件，请联系公司支持。',
  ssh_prepared: 'SSH 配置已准备，尚未验证连接。',
  ssh_ready:
    'SSH、用户、工作目录及远端 Codex 命令已检查。尚未添加 Codex Desktop 项目。',
  unreachable: '连接或远端用户、目录检查未通过，请检查公司网络后重试。',
  network_required: '请先连接公司网络，再准备或检查此开发机。',
  binding_changed: '授权配置已更新，请刷新开发机清单后重试。',
  key_mismatch: '下载的 SSH 密钥与授权指纹不一致，已停止安装，请联系管理员。',
  host_key_conflict:
    '开发机主机身份与可信记录不一致，已停止连接，请联系管理员核验。',
  permission_denied: 'SSH 身份未获目标主机授权，请联系管理员。',
  desktop_config_conflict:
    'SSH 配置已准备，但个人 SSH 设置影响 Desktop 连接，请联系公司支持。',
  codex_unavailable:
    'SSH 可用，远端登录环境未找到 Codex 命令，请联系公司支持。',
}

export const WorkspaceRemote = ({
  client,
  sessionState,
}: {
  client: WorkspaceClient
  sessionState?: string
}) => {
  const requestRef = useRef(0)
  const [listing, setListing] = useState<WorkspaceRemoteStatus | null>(null)
  const [result, setResult] = useState<WorkspaceRemoteStatus | null>(null)
  const [pending, setPending] = useState(false)
  const run = useCallback(
    async (
      action: WorkspaceRemoteAction,
      hostId?: string,
      workspaceId?: string,
    ) => {
      if (!client.remote) return
      const id = ++requestRef.current
      if (action === 'hosts') setListing(null)
      setPending(true)
      setResult(null)
      try {
        const next = await client.remote(action, hostId, workspaceId)
        if (id !== requestRef.current) return
        if (action === 'hosts') setListing(next)
        else setResult(next)
      } catch {
        if (id !== requestRef.current) return
        setResult({
          state: 'unavailable',
          hosts: [],
          alias: null,
          path: null,
          code: null,
        })
      } finally {
        if (id === requestRef.current) setPending(false)
      }
    },
    [client],
  )
  useEffect(() => {
    void run('hosts')
    return () => {
      requestRef.current += 1
    }
  }, [run, sessionState])
  const current = result || listing
  return (
    <section
      className="workspace-service"
      aria-label="远程开发机"
      aria-busy={pending}
    >
      <p className="workspace-index">03 / REMOTE DEVELOPMENT</p>
      <h2>个人远程开发机</h2>
      <p role="status">
        {pending
          ? '正在检查开发机，请稍候…'
          : current
            ? messages[current.state]
            : '公司开发机自动接入服务尚未就绪，无需手动填写服务器信息。'}
      </p>
      {current?.code && <p>错误码：{current.code}</p>}
      <button
        disabled={pending || !client.remote}
        onClick={() => void run('hosts')}
      >
        刷新开发机
      </button>
      {listing?.hosts.map((host) => (
        <div key={host.id} className="workspace-remote-host">
          <h3>{host.display_name}</h3>
          <p>
            网络条件：
            {host.network_requirement === 'company_proxy'
              ? '先连接公司网络'
              : host.network_requirement === 'tailscale'
                ? '需要 Tailscale 网络'
                : '可直接连接'}
          </p>
          {host.workspaces.map((workspace) => (
            <div key={workspace.id}>
              <p>
                {workspace.display_name}
                {workspace.path && (
                  <>
                    {' '}
                    · <code>{workspace.path}</code>
                  </>
                )}
              </p>
              <div className="workspace-login-options">
                <button
                  disabled={pending}
                  onClick={() => void run('prepare', host.id, workspace.id)}
                >
                  准备 SSH
                </button>
                <button
                  disabled={pending}
                  onClick={() => void run('check', host.id, workspace.id)}
                >
                  检查连接
                </button>
              </div>
            </div>
          ))}
        </div>
      ))}
      {result?.state === 'ssh_ready' && result.alias && result.path && (
        <div className="workspace-command">
          <p>
            在 Codex Desktop 设置 → Connections
            中添加或启用以下主机，再选择工作目录：
          </p>
          <p>
            主机：<code>{result.alias}</code>
            <br />
            工作目录：<code>{result.path}</code>
          </p>
          <p>打开项目并完成一次远程任务后，才算远程开发环境验收完成。</p>
        </div>
      )}
    </section>
  )
}
