import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import type { VueWrapper } from '@vue/test-utils'
import AdminPage from './pages/AdminPage.vue'

const targetUuid = 'b530108c-fc07-4097-9866-34b19d2fe818'
const adminAccount = { sub: '6442eccc-9153-48c7-ae69-811ba6f75836', auth_epoch: 1, login_id: '6442eccc-9153-48c7-ae69-811ba6f75836', method: 'PASSWORD', authenticated_at: '2026-10-23T00:00:00Z', password_recent: true, must_change_password: false, roles: ['ROLE_SYSTEM_ADMIN'], mfa: { enrolled: false, required: false, recent: false, recovery_required: false } }
const plainAccount = { ...adminAccount, roles: ['ROLE_USER'] }
const auditEntry = { id: '11111111-1111-1111-1111-111111111111', createdAt: '2026-10-23T00:01:00Z', subject: targetUuid, action: 'ROLE_GRANTED', result: 'SUCCESS', clientId: null, operationId: '22222222-2222-2222-2222-222222222222', detail: { role: 'ROLE_ADMIN_PASSWORD_RESET', reason: '客服工单确认' } }
const csrf = { header_name: 'X-CSRF-TOKEN', parameter_name: '_csrf', token: 'admin-csrf-proof' }
let wrappers: VueWrapper[] = []
const body = (value: unknown, status = 200) => new Response(status === 204 ? null : JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })

beforeEach(() => { window.history.replaceState(null, '', '/portal/admin') })
afterEach(() => { wrappers.forEach(wrapper => wrapper.unmount()); wrappers = []; vi.unstubAllGlobals(); document.body.innerHTML = '' })
function attach(): VueWrapper {
  const wrapper = mount(AdminPage); wrappers.push(wrapper); return wrapper
}

describe('admin console', () => {
  it('hides everything and fetches nothing when the account is not an operator', async () => {
    const fetcher = vi.fn(async (path: string) => path === '/api/session/me' ? body(plainAccount) : body({ error: 'MUST_NOT_CALL' }))
    vi.stubGlobal('fetch', fetcher)
    await attach()
    const wrapper = wrappers[0]!; await flushPromises()
    expect(wrapper.text()).toContain('没有管理控制台权限')
    expect(fetcher.mock.calls.filter(([path]) => String(path).startsWith('/api/admin/console/'))).toHaveLength(0)
  })

  it('lists audit entries newest first and continues by validated cursor', async () => {
    const auditCalls: string[] = []
    vi.stubGlobal('fetch', vi.fn(async (path: string) => {
      if (path === '/api/session/me') return body(adminAccount)
      if (path.startsWith('/api/admin/console/audit')) { auditCalls.push(path); return body(auditCalls.length === 1 ? { entries: [auditEntry], nextCursor: 'MTIzNDU2Nzg5MDEyMzQ1NnxkZWFkLTBmb2Y-' } : { entries: [], nextCursor: null }) }
      return body({ error: 'MUST_NOT_CALL' })
    }))
    const wrapper = attach(); await flushPromises()
    expect(wrapper.text()).toContain('ROLE_GRANTED')
    expect(wrapper.text()).toContain('客服工单确认')
    const more = wrapper.findAll('button').find(button => button.text().includes('加载更多记录'))
    expect(more).toBeDefined()
    await more!.trigger('click'); await flushPromises()
    expect(auditCalls).toEqual(['/api/admin/console/audit', '/api/admin/console/audit?cursor=MTIzNDU2Nzg5MDEyMzQ1NnxkZWFkLTBmb2Y-'])
  })

  it('grants a role only with a target, a reason row and a private idempotency key', async () => {
    let postedPath = ''; let postedKey = ''; let postedBody: Record<string, unknown> = {}
    vi.stubGlobal('fetch', vi.fn(async (path: string, init?: RequestInit) => {
      if (path === '/api/session/me') return body(adminAccount)
      if (path.startsWith('/api/admin/console/audit')) return body({ entries: [], nextCursor: null })
      if (path === '/api/public/csrf') return body(csrf)
      if (init?.method === 'POST') {
        postedPath = path; postedKey = (init.headers as Record<string, string>)['Idempotency-Key']!
        postedBody = JSON.parse(String(init.body)) as Record<string, unknown>
        return body(null, 204)
      }
      if (path.startsWith(`/api/admin/console/users/${targetUuid}/roles`)) return body([])
      return body({ error: 'MUST_NOT_CALL' })
    }))
    const wrapper = attach(); await flushPromises()
    await wrapper.get('#admin-target').setValue(targetUuid)
    await wrapper.get('#admin-target').trigger('blur'); await flushPromises()
    await wrapper.get('#admin-reason').setValue('审计联动交接')
    await wrapper.get('form').trigger('submit'); await flushPromises()
    expect(postedPath).toBe(`/api/admin/console/users/${targetUuid}/roles`)
    expect(postedBody).toEqual({ action: 'GRANT', role: 'ROLE_SYSTEM_ADMIN', reason: '审计联动交接' })
    expect(postedKey).toMatch(/^[0-9a-f-]{36}$/)
    expect(wrapper.text()).toContain('角色已授予')
  })

  it('never sends a raw cursor back without validation', async () => {
    const fetcher = vi.fn(async (path: string) => path === '/api/session/me' ? body(adminAccount) : body({ entries: [], nextCursor: '../escape' }))
    vi.stubGlobal('fetch', fetcher)
    const wrapper = attach(); await flushPromises()
    const more = wrapper.findAll('button').find(button => button.text().includes('加载更多记录'))
    expect(more).toBeDefined()
    await more!.trigger('click'); await flushPromises()
    // The malicious cursor is rejected client-side before any further request, and never rendered.
    const auditPaths = fetcher.mock.calls.map(([path]) => String(path)).filter(path => path.startsWith('/api/admin/console/audit'))
    expect(auditPaths).toHaveLength(1)
    expect(wrapper.text()).not.toContain('../escape')
  })
})
