export interface Csrf { header_name: string; parameter_name: string; token: string }
export interface MfaStatus { enrolled: boolean; required: boolean; recent: boolean; recovery_required: boolean }
export interface Identity { sub: string; auth_epoch: number; login_id: string; method: string; password_recent: boolean; must_change_password: boolean; authenticated_at: string; roles?: string[]; mfa: MfaStatus }
export interface PasswordOperation { id: string; state: 'PREPARED' | 'UNKNOWN' | 'COMMITTED' | 'REJECTED'; errorCode?: string }
export interface Enrollment { secret: string; otpauthUri: string; expiresAt: string }
export interface Replacement extends Enrollment { id: string }
export interface LoginEntry { id: string; authenticatedAt: string; lastAccessAt: string; method: string; device: string; current: boolean }
export interface LoginPage { entries: LoginEntry[]; nextCursor: string | null }
export interface AdminAuditEntry { id: string; createdAt: string; subject: string | null; action: string; result: string; clientId: string | null; operationId: string | null; detail: Record<string, string> }
export interface AdminAuditPage { entries: AdminAuditEntry[]; nextCursor: string | null }

export const isUuid = (value: unknown): value is string => typeof value === 'string' && /^[a-f\d]{8}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{12}$/i.test(value)
export class ApiFailure extends Error {
  constructor(readonly status: number, readonly code = '', readonly operationId?: string) { super('Request failed') }
}
async function decode(response: Response): Promise<unknown> {
  if (response.status === 204) return undefined
  let data: Record<string, unknown> = {}
  if (response.headers.get('content-type')?.includes('application/json')) {
    try { data = await response.json() as Record<string, unknown> } catch { throw new ApiFailure(502) }
  }
  if (!response.ok) throw new ApiFailure(response.status, typeof data.error === 'string' ? data.error : '', isUuid(data.operation_id) ? data.operation_id : undefined)
  if (!response.headers.get('content-type')?.includes('application/json')) throw new ApiFailure(502)
  return data
}
/** Shared guard for the portal API surface: rejects non-/api/ targets and fragments before any network call. */
function assertApiPath(path: string): void {
  if (!path.startsWith('/api/') || path.includes('#')) throw new ApiFailure(400)
}
async function send(path: string, init: RequestInit): Promise<Response> {
  assertApiPath(path)
  try { return await fetch(path, { credentials: 'same-origin', cache: 'no-store', redirect: 'error', ...init }) }
  catch { throw new ApiFailure(0) }
}
export async function get<T>(path: string, signal?: AbortSignal): Promise<T> {
  return await decode(await send(path, { method: 'GET', headers: { Accept: 'application/json' }, signal })) as T
}
export async function csrf(): Promise<Csrf> { return get<Csrf>('/api/public/csrf') }
export async function post<T>(path: string, body: unknown = {}, key?: string): Promise<T> {
  // Validate the target before the CSRF proof is fetched so a rejected path never opens a session.
  assertApiPath(path)
  const proof = await csrf()
  const headers: Record<string, string> = { Accept: 'application/json', 'Content-Type': 'application/json', [proof.header_name]: proof.token }
  if (key) headers['Idempotency-Key'] = key
  return await decode(await send(path, { method: 'POST', headers, body: JSON.stringify(body) })) as T
}
export async function logout(): Promise<void> {
  const proof = await csrf()
  let response: Response
  try { response = await fetch('/logout', { method: 'POST', credentials: 'same-origin', redirect: 'manual', headers: { [proof.header_name]: proof.token } }) }
  catch { throw new ApiFailure(0) }
  if (response.type !== 'opaqueredirect' && response.status !== 302) throw new ApiFailure(response.status)
  window.location.assign('/login?logout')
}
/** Opaque server cursor guard: only validated base64url shapes are ever sent back. */
export function assertCursor(cursor: string | null | undefined): void {
  if (cursor === null || cursor === undefined) return
  if (!/^[A-Za-z0-9_-]{16,512}$/.test(cursor)) throw new ApiFailure(400)
}
export function message(error: unknown): string {  if (!(error instanceof ApiFailure)) return '暂时无法完成操作，请稍后重试。'
  const known: Record<string, string> = {
    POLICY_REJECTED: '新密码未满足安全策略，请检查长度、字符组合以及是否包含个人信息。',
    OLD_PASSWORD_INCORRECT: '当前密码验证失败，请重新输入。',
    RECENT_AUTH_REQUIRED: '请先重新验证当前密码。',
    RATE_LIMITED: '操作过于频繁，请稍后再试。',
    DIRECTORY_POLICY_NOT_VERIFIED: '此密码操作尚未开放，请联系管理员。',
  }
  if (known[error.code]) return known[error.code]
  if (error.status === 401) return '登录或验证已失效，请重新登录。'
  if (error.status === 403) return '操作未通过安全验证，请确认密码及多因素验证，或刷新页面后重试。'
  if (error.status === 429) return '操作过于频繁，请稍后再试。'
  if (error.status === 0) return '连接中断，暂时无法确认操作结果。'
  if (error.status >= 500) return '服务暂不可用，请稍后查询处理结果。'
  return '操作或验证码已失效，请重新发起验证。'
}
