import { useCallback, useEffect, useState } from 'react'

import type {
  WorkspaceAction,
  WorkspaceClient,
  WorkspaceConfiguration,
  WorkspaceStatus,
} from '@/services/workspace'
import { workspaceErrorMessage } from '@/services/workspace'

import { WorkspaceRemote } from './workspace-remote'

import './workspace.css'

interface Props {
  client: WorkspaceClient
  page?: 'workbench' | 'development' | 'settings'
  onDiagnostics?: () => void
}

const networkStages: Record<string, string> = {
  download_failed: '个人配置下载未完成，原有配置已保留。',
  validation_failed: '个人配置未通过校验，原有配置已保留。',
  import_failed: '个人配置导入未完成，原有配置已保留。',
  activation_failed: '个人配置启用未完成，原有配置仍保留。',
  proxy_enable_failed: '配置已导入，系统代理切换未完成。',
  system_proxy_enabled_reachability_unverified:
    '个人配置已下载、校验并导入；系统代理已启用，目标工作服务仍待验证。',
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
        const notices: string[] = []
        if (next.remote_revoked === false) {
          notices.push('本机已退出，但服务端凭据撤销未完成。请联系管理员处理。')
        }
        if (next.system_proxy_closed === false) {
          notices.push(
            'Passport 已退出，但本应用 ClashVerge 系统代理接管未能关闭。请检查系统代理状态。',
          )
        }
        if (notices.length) setError(notices.join(' '))
      } catch (failure) {
        setError(workspaceErrorMessage(failure))
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
  const networkUnassigned =
    status?.company &&
    signedIn &&
    (status.code === 'MEMBER_NOT_REGISTERED' ||
      status.capabilities?.network === 'not_granted')
  const action = (value: WorkspaceAction) => () => {
    void run(value)
  }
  const titles = {
    workbench: '让工作环境，准备就绪。',
    development: '开发环境',
    settings: '工作环境设置',
  }
  const configurations = status?.configurations ?? []
  const sshConfigurations = configurations.filter((item) => item.kind === 'ssh')
  // The People catalogue identifies the managed network by kind (`mihomo`).
  // Older Passport snapshots used the semantic id `network`; accepting both
  // keeps the UI stable while preserving the server-issued configuration id
  // for installation evidence and reports.
  const networkConfiguration =
    configurations.find((item) => item.kind === 'mihomo') ??
    configurations.find((item) => item.id === 'network') ??
    null
  const [selectedResource, setSelectedResource] = useState('network')
  const activeResource =
    selectedResource.startsWith('ssh:') &&
    !sshConfigurations.some(
      (item) => item.id === selectedResource.slice('ssh:'.length),
    )
      ? 'network'
      : selectedResource
  const selectedConfiguration = (id: string): WorkspaceConfiguration | null =>
    id === 'network'
      ? networkConfiguration
      : (configurations.find((item) => item.id === id) ?? null)
  const resourceStatus = (configuration: WorkspaceConfiguration | null) => {
    if (!configuration) return '未分配'
    if (configuration.preparation === 'not_ready') return '管理员准备中'
    const report = status?.installation_reports?.find(
      (item) =>
        item.configuration_id === configuration.id &&
        item.revision === configuration.revision,
    )
    if (!report) return '待本机应用'
    if (report.stage === 'failed') return '本机验证失败'
    if (report.stage === 'verified') return '本机已验证'
    if (report.stage === 'applied') return '已应用，待验证'
    return '已领取'
  }
  const configurationEvidence = (
    configuration: WorkspaceConfiguration | null,
  ) => {
    if (!configuration) return null
    const report = status?.installation_reports?.find(
      (item) =>
        item.configuration_id === configuration.id &&
        item.revision === configuration.revision,
    )
    return (
      <details className="workspace-evidence-details">
        <summary>配置与证据</summary>
        <dl>
          <dt>revision</dt>
          <dd>{configuration.revision}</dd>
          <dt>管理员准备</dt>
          <dd>{configuration.preparation}</dd>
          <dt>本机报告</dt>
          <dd>
            {report
              ? `${report.stage}${report.error_code ? ` · ${report.error_code}` : ''}`
              : '暂无'}
          </dd>
          {configuration.observation?.status && (
            <>
              <dt>管理员观察</dt>
              <dd>
                {configuration.observation.status}
                {configuration.observation.reason
                  ? ` · ${configuration.observation.reason}`
                  : ''}
              </dd>
            </>
          )}
          {report?.source && (
            <>
              <dt>报告来源</dt>
              <dd>{report.source}</dd>
            </>
          )}
        </dl>
      </details>
    )
  }

  return (
    <main className="workspace-shell" aria-busy={pending !== null}>
      <header className="workspace-heading">
        <div>
          <p className="workspace-eyebrow">WORKSPACE / {page.toUpperCase()}</p>
          <h1>Pilgrim Works</h1>
          <p className="workspace-intro">{titles[page]}</p>
        </div>
        <button
          type="button"
          disabled={pending !== null}
          onClick={action('status')}
        >
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
      {status?.code && (
        <div className="workspace-message" role="status">
          {workspaceErrorMessage({ code: status.code })}
        </div>
      )}
      {status?.catalogue_code && (
        <div className="workspace-message" role="status">
          {workspaceErrorMessage({ code: status.catalogue_code })}
        </div>
      )}
      {status?.installation_code && (
        <div className="workspace-message" role="status">
          {workspaceErrorMessage({ code: status.installation_code })}
        </div>
      )}
      {status?.state === 'unconfigured' && (
        <div className="workspace-message">
          公司自动接入服务尚未就绪，暂时无法登录。无需手动填写配置，请等待公司接入完成。
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
            (status.state === 'signed_out' ||
            status.state === 'unconfigured' ? (
              <div className="workspace-login-options">
                {(status.state === 'unconfigured' ||
                  status.providers?.includes('feishu')) && (
                  <button
                    type="button"
                    className="workspace-primary"
                    disabled={
                      pending !== null || status.state === 'unconfigured'
                    }
                    onClick={action('login_feishu')}
                  >
                    飞书登录
                  </button>
                )}
                {!status.company && status.providers?.includes('authentik') && (
                  <button
                    type="button"
                    disabled={
                      pending !== null || status.state === 'unconfigured'
                    }
                    onClick={action('login_authentik')}
                  >
                    企业 SSO 登录
                  </button>
                )}
              </div>
            ) : (
              <button
                type="button"
                disabled={pending !== null}
                onClick={action('logout')}
              >
                退出登录并断开
              </button>
            ))}
        </section>
      )}

      {page !== 'settings' && page === 'workbench' && (
        <div className="workspace-workbench">
          <nav className="workspace-resource-index" aria-label="工作资源">
            <p className="workspace-index">资源索引</p>
            <button
              type="button"
              className={activeResource === 'network' ? 'active' : ''}
              onClick={() => setSelectedResource('network')}
            >
              <span>公司网络</span>
              <small>{resourceStatus(selectedConfiguration('network'))}</small>
            </button>
            <button
              type="button"
              className={activeResource === 'codex' ? 'active' : ''}
              onClick={() => setSelectedResource('codex')}
            >
              <span>Codex 本地配置</span>
              <small>{status?.codex ? '已写入' : '待写入'}</small>
            </button>
            {sshConfigurations.map((configuration) => (
              <button
                type="button"
                key={configuration.id}
                className={
                  activeResource === `ssh:${configuration.id}` ? 'active' : ''
                }
                onClick={() => setSelectedResource(`ssh:${configuration.id}`)}
              >
                <span>{configuration.id.replace(/^ssh-/, '')}</span>
                <small>{resourceStatus(configuration)}</small>
              </button>
            ))}
            {!signedIn && (
              <p className="workspace-index-note">登录后显示已分配的资源。</p>
            )}
          </nav>

          <section className="workspace-resource-detail" aria-live="polite">
            {activeResource === 'network' && (
              <section className="workspace-service">
                <p className="workspace-index">01 / CONNECTIVITY</p>
                <h2>公司网络 · ClashVerge / mihomo</h2>
                <span className="workspace-status">
                  {status
                    ? status.network_enabled
                      ? '系统连接已启用'
                      : networkUnassigned
                        ? '尚未分配'
                        : '未连接'
                    : '状态待确认'}
                </span>
                {status?.network_stage && (
                  <p role="status">{networkStages[status.network_stage]}</p>
                )}
                <p>
                  领取当前 network revision，交给现有 ClashVerge / mihomo
                  核心校验、导入并接管系统代理。
                </p>
                <p className="workspace-evidence">
                  管理员：{resourceStatus(selectedConfiguration('network'))} ·
                  revision：
                  {selectedConfiguration('network')?.revision ?? '—'}
                </p>
                {configurationEvidence(selectedConfiguration('network'))}
                <button
                  type="button"
                  disabled={
                    pending !== null ||
                    (!signedIn && !status?.network_enabled) ||
                    (status?.company === true &&
                      status.capabilities?.network !== 'granted' &&
                      !status.network_enabled)
                  }
                  onClick={action(
                    status?.network_enabled ? 'disconnect' : 'connect',
                  )}
                >
                  {status?.network_enabled ? '断开连接' : '连接公司网络'}
                </button>
                {status?.network_enabled && (
                  <button
                    type="button"
                    disabled={pending !== null || !signedIn}
                    onClick={action('update')}
                  >
                    更新公司网络配置
                  </button>
                )}
              </section>
            )}
            {activeResource === 'codex' && (
              <section className="workspace-service">
                <p className="workspace-index">02 / CODEX</p>
                <h2>Codex 本地配置</h2>
                <span className="workspace-status">
                  {status?.codex
                    ? '受管 profile / helper 已写入'
                    : '受管配置待写入'}
                </span>
                <p>
                  写入 App 所有的受管 profile / helper；Codex provider
                  定义、地址、名称和路由保持不变。
                </p>
                <button
                  type="button"
                  disabled={pending !== null || !signedIn}
                  onClick={action('configure')}
                >
                  {status?.codex ? '重新写入 Codex 配置' : '写入 Codex 配置'}
                </button>
                {status?.codex && (
                  <p className="workspace-command">
                    provider 保持不变；已写入的受管配置可在 Codex 中继续使用。
                  </p>
                )}
                <p className="workspace-evidence">
                  本机动作：{status?.codex ? '受管配置已写入' : '等待写入'} ·
                  provider：只读
                </p>
                <details className="workspace-evidence-details">
                  <summary>配置与证据</summary>
                  <p>
                    受管 profile / helper 由本机写入；现有 Codex provider
                    保持不变。
                  </p>
                </details>
              </section>
            )}
            {(activeResource.startsWith('ssh:') ||
              (configurations.length === 0 && status?.company !== true)) && (
              <WorkspaceRemote
                client={client}
                sessionState={`${status?.state}:${status?.provider ?? ''}`}
                selectedHostId={
                  activeResource.startsWith('ssh:')
                    ? activeResource.slice('ssh:'.length).replace(/^ssh-/, '')
                    : undefined
                }
              />
            )}
            {activeResource.startsWith('ssh:') &&
              selectedConfiguration(activeResource.slice('ssh:'.length)) && (
                <p className="workspace-evidence workspace-resource-meta">
                  管理员：
                  {resourceStatus(
                    selectedConfiguration(activeResource.slice('ssh:'.length)),
                  )}{' '}
                  · 写入目标：~/.ssh/config · revision：
                  {
                    selectedConfiguration(activeResource.slice('ssh:'.length))
                      ?.revision
                  }
                </p>
              )}
            {activeResource.startsWith('ssh:') &&
              configurationEvidence(
                selectedConfiguration(activeResource.slice('ssh:'.length)),
              )}
          </section>
        </div>
      )}

      {page !== 'settings' && page !== 'workbench' && (
        <WorkspaceRemote
          client={client}
          sessionState={`${status?.state}:${status?.provider ?? ''}`}
        />
      )}

      {page === 'settings' && (
        <section className="workspace-service">
          <h2>支持与诊断</h2>
          <p>
            企业接入由公司统一提供。需要排查连接问题时，可以打开高级网络设置。
          </p>
          <button
            type="button"
            onClick={onDiagnostics}
            disabled={!onDiagnostics}
          >
            高级网络设置
          </button>
          <p>
            退出登录会清除本机登录凭据，并尝试撤销服务端会话及断开公司网络。已安装的
            SSH 密钥和配置默认保留；退出不会撤销已有 SSH 访问。
          </p>
        </section>
      )}
      <footer className="workspace-footer">
        Pilgrim Works · 仅限内部使用 <span>基于 Clash Verge Rev · GPL-3.0</span>
      </footer>
    </main>
  )
}
