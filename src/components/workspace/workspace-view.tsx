import { useCallback, useEffect, useState } from 'react'

import type {
  WorkspaceAction,
  WorkspaceClient,
  WorkspaceStatus,
} from '@/services/workspace'

import './workspace.css'

interface Props {
  client: WorkspaceClient
  page?: 'workbench' | 'development' | 'settings'
  onDiagnostics?: () => void
}

const states = {
  unconfigured: '等待接入',
  signed_out: '未登录',
  signed_in: '已登录',
  expired: '登录已过期',
}

export const WorkspaceView = ({
  client,
  page = 'workbench',
  onDiagnostics,
}: Props) => {
  const [status, setStatus] = useState<WorkspaceStatus | null>(null)
  const [pending, setPending] = useState<WorkspaceAction | null>('status')
  const [error, setError] = useState('')

  const run = useCallback(
    async (action: WorkspaceAction) => {
      setPending(action)
      setError('')
      try {
        const next = await client.run(action)
        setStatus(next)
        if (next.remote_revoked === false) {
          setError('本机已退出，但服务端凭据撤销未完成。请联系管理员处理。')
        }
      } catch {
        setError('操作未完成。请检查企业配置、系统凭据库与网络，然后重试。')
        try {
          setStatus(await client.run('status'))
        } catch {
          setStatus(null)
        }
      } finally {
        setPending(null)
      }
    },
    [client],
  )

  useEffect(() => {
    void run('status')
  }, [run])

  const signedIn = status?.state === 'signed_in'
  const action = (value: WorkspaceAction) => () => {
    void run(value)
  }
  const titles = {
    workbench: '让工作环境，准备就绪。',
    development: '开发环境',
    settings: '工作环境设置',
  }

  return (
    <main className="workspace-shell" aria-busy={pending !== null}>
      <header className="workspace-heading">
        <div>
          <p className="workspace-eyebrow">WORKSPACE / {page.toUpperCase()}</p>
          <h1>Pilgrim Works</h1>
          <p className="workspace-intro">{titles[page]}</p>
        </div>
        <button disabled={pending !== null} onClick={action('status')}>
          检查状态
        </button>
      </header>

      {error && (
        <div className="workspace-message workspace-error" role="alert">
          {error}
        </div>
      )}
      {pending && (
        <div className="workspace-message" role="status">
          {pending.startsWith('login')
            ? '请在系统浏览器中完成企业登录，最长等待两分钟。'
            : '正在处理，请稍候…'}
        </div>
      )}
      {status?.state === 'unconfigured' && (
        <div className="workspace-message">
          尚未接入企业环境。请由管理员安装伴随服务并提供本机企业配置。
        </div>
      )}

      {page !== 'development' && (
        <section className="workspace-identity" aria-label="企业账号">
          <div className="workspace-avatar" aria-hidden="true">
            {status?.name?.slice(0, 1) || 'P'}
          </div>
          <div className="workspace-identity-text">
            <h2>{status?.name || '连接你的工作账号'}</h2>
            <p>
              {status ? states[status.state] : '状态待确认'} ·{' '}
              {status?.provider === 'feishu'
                ? '飞书'
                : status?.provider === 'authentik'
                  ? '企业 SSO'
                  : '企业统一身份认证'}
            </p>
          </div>
          {status &&
            status.state !== 'unconfigured' &&
            (status.state === 'signed_out' ? (
              <div className="workspace-login-options">
                {status.providers?.includes('feishu') && (
                  <button
                    className="workspace-primary"
                    disabled={pending !== null}
                    onClick={action('login_feishu')}
                  >
                    飞书登录
                  </button>
                )}
                {status.providers?.includes('authentik') && (
                  <button
                    disabled={pending !== null}
                    onClick={action('login_authentik')}
                  >
                    企业 SSO 登录
                  </button>
                )}
              </div>
            ) : (
              <button disabled={pending !== null} onClick={action('logout')}>
                退出登录并断开
              </button>
            ))}
        </section>
      )}

      {page !== 'settings' && (
        <div className="workspace-services">
          {page === 'workbench' && (
            <section className="workspace-service">
              <p className="workspace-index">01 / CONNECTIVITY</p>
              <h2>公司网络</h2>
              <span className="workspace-status">
                {status
                  ? status.network_enabled
                    ? '系统连接已启用'
                    : '未连接'
                  : '状态待确认'}
              </span>
              <p>
                按企业授权配置访问工作资源。系统连接状态不代表所有内部服务均可访问。
              </p>
              <button
                disabled={
                  pending !== null || (!signedIn && !status?.network_enabled)
                }
                onClick={action(
                  status?.network_enabled ? 'disconnect' : 'connect',
                )}
              >
                {status?.network_enabled ? '断开连接' : '连接公司网络'}
              </button>
            </section>
          )}
          <section className="workspace-service">
            <p className="workspace-index">02 / DEVELOPMENT</p>
            <h2>AI 开发环境</h2>
            <span className="workspace-status">
              {status?.codex ? 'Codex 已配置' : 'Codex 待配置'}
            </span>
            <p>同步公司的模型设置，凭据按需获取。保留你的其他开发配置。</p>
            <button
              disabled={pending !== null || !signedIn}
              onClick={action('configure')}
            >
              同步 Codex 配置
            </button>
            {status?.codex && (
              <p className="workspace-command">
                启动：<code>codex --profile pilgrim</code>
                <br />
                {signedIn
                  ? '已配置；模型可用性需在 Codex 中验证。'
                  : '请先登录，再使用公司模型。'}
              </p>
            )}
          </section>
        </div>
      )}

      {page === 'settings' && (
        <section className="workspace-service">
          <h2>支持与诊断</h2>
          <p>
            企业账号和配置由管理员提供。需要排查连接问题时，可以打开高级网络设置。
          </p>
          <button onClick={onDiagnostics} disabled={!onDiagnostics}>
            高级网络设置
          </button>
          <p>
            退出登录会清除本机登录凭据，并尝试撤销服务端会话及断开公司网络。
          </p>
        </section>
      )}
      <footer className="workspace-footer">
        Pilgrim Works · 仅限内部使用 <span>基于 Clash Verge Rev · GPL-3.0</span>
      </footer>
    </main>
  )
}
