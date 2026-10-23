<script setup lang="ts">
import { ref, watch } from 'vue'
import { assertCursor, get, isUuid, message, post } from '../api'
import type { AdminAuditEntry, AdminAuditPage } from '../api'
import { useAccount } from '../flow'

const assignable: string[] = ['ROLE_SYSTEM_ADMIN', 'ROLE_ADMIN_PASSWORD_RESET', 'ROLE_ADMIN_PASSWORD_RECOVERY', 'ROLE_ADMIN_MFA_RECOVERY']
const { identity, error: accountError } = useAccount()
const audit = ref<AdminAuditEntry[]>([]); const cursor = ref<string | null>(null); const error = ref(''); const busy = ref(false)
const target = ref(''); const roles = ref<string[]>([]); const role = ref<string>(assignable[0]!)
const reason = ref(''); const rolesError = ref(''); const rolesBusy = ref(false); const notice = ref('')

async function loadAudit(more = false) {
  if (busy.value) return
  busy.value = true; error.value = ''
  try {
    if (more) assertCursor(cursor.value)
    const page = await get<AdminAuditPage>('/api/admin/console/audit' + (more && cursor.value ? '?cursor=' + cursor.value : ''))
    audit.value = more ? [...audit.value, ...page.entries] : page.entries; cursor.value = page.nextCursor
  } catch (failure) { error.value = message(failure) } finally { busy.value = false }
}
async function loadRoles(freshTarget = false) {
  if (rolesBusy.value) return
  resetRoleForm(freshTarget)
  if (!isUuid(target.value)) { if (target.value) rolesError.value = '请输入有效的用户编号。'; return }
  rolesBusy.value = true; rolesError.value = ''
  try { roles.value = await get<string[]>(`/api/admin/console/users/${target.value}/roles`) }
  catch (failure) { roles.value = []; rolesError.value = message(failure) } finally { rolesBusy.value = false }
}
function resetRoleForm(freshTarget: boolean): void {
  if (freshTarget) roles.value = []
  notice.value = ''; if (rolesError.value) rolesError.value = ''
}
async function changeKind(action: 'GRANT' | 'REVOKE') {
  if (rolesBusy.value || !isUuid(target.value)) { if (!isUuid(target.value)) rolesError.value = '请输入有效的用户编号。'; return }
  if (!reason.value.trim()) { rolesError.value = '请填写操作原因。'; return }
  rolesBusy.value = true; rolesError.value = ''; notice.value = ''
  try {
    await post(`/api/admin/console/users/${target.value}/roles`,
      { action, role: role.value, reason: reason.value.trim() }, crypto.randomUUID())
    if (action === 'GRANT' && !roles.value.includes(role.value)) roles.value = [...roles.value, role.value].sort()
    if (action === 'REVOKE') roles.value = roles.value.filter(existing => existing !== role.value)
    notice.value = action === 'GRANT' ? '角色已授予，可在审计记录中核对。' : '角色已撤销，可在审计记录中核对。'
    reason.value = ''
  } catch (failure) { rolesError.value = message(failure) } finally { rolesBusy.value = false }
}

watch(identity, value => { if (value) {
  if (value.roles?.includes('ROLE_SYSTEM_ADMIN')) void loadAudit(); else error.value = '此账户没有管理控制台权限。'
} })
function inRoles(roleValue: string): boolean { return roles.value.includes(roleValue) }
function detailText(entry: AdminAuditEntry): string {
  const parts: string[] = []
  if (entry.detail.role) parts.push('角色 ' + entry.detail.role)
  if (entry.detail.reason) parts.push('原因 ' + entry.detail.reason)
  if (entry.detail.replay) parts.push('重放 ' + entry.detail.replay)
  return parts.join(' · ')
}
</script>
<template>
  <header class="page-heading"><span class="eyebrow">管理控制台</span><h1>审计与角色</h1><p>查询控制台审计记录，授予或撤销管理角色。所有写操作都会留痕。</p></header>
  <p v-if="accountError || error" role="alert" class="error">{{ accountError || error }}</p>
  <template v-if="identity && identity.roles?.includes('ROLE_SYSTEM_ADMIN')">
    <section class="card"><h2>审计记录</h2><p class="muted">最新优先，每次最多 100 条；导出的 CSV 仅限 1000 行。</p>
      <ul class="session-list"><li v-for="entry in audit" :key="entry.id"><div><h3>{{ entry.action }} <span class="badge" :class="entry.result === 'SUCCESS' ? 'good' : ''">{{ entry.result }}</span></h3><p>{{ new Date(entry.createdAt).toLocaleString() }}<template v-if="entry.subject"> · 对象 {{ entry.subject }}</template></p><p class="muted" v-if="detailText(entry)">{{ detailText(entry) }}</p></div></li></ul>
      <p v-if="busy" role="status">正在加载…</p><p v-else-if="!audit.length && !error">暂无审计记录。</p><button v-if="cursor" class="secondary" :disabled="busy" @click="loadAudit(true)">加载更多记录</button>
    </section>
    <section class="card"><h2>管理角色</h2><p class="muted">仅允许操作员人不可推导的固定角色集合；同一幂等键重放同一上下文会被拒绝。</p>
      <form @submit.prevent="changeKind('GRANT')">
        <p><label for="admin-target">用户编号（UUID）</label><input id="admin-target" v-model="target" autocomplete="off" spellcheck="false" placeholder="00000000-0000-0000-0000-000000000000" @blur="loadRoles(true)" /></p>
        <p v-if="roles.length">现有角色：{{ roles.join('、') }}</p><p v-else-if="target && !rolesBusy && isUuid(target)">该对象暂无可显示角色。</p>
        <p><label for="admin-role">角色</label><select id="admin-role" v-model="role"><option v-for="option in assignable" :key="option" :value="option">{{ option }}</option></select></p>
        <p><label for="admin-reason">操作原因</label><textarea id="admin-reason" v-model="reason" required maxlength="500" autocomplete="off"></textarea></p>
        <div class="actions"><button type="button" class="secondary" :disabled="rolesBusy || !inRoles(role)" @click="changeKind('REVOKE')">撤销角色</button><button type="submit" :disabled="rolesBusy || inRoles(role)">授予角色</button></div>
      </form>
      <p v-if="rolesBusy" role="status">正在处理…</p>
      <p v-if="rolesError" role="alert" class="error">{{ rolesError }}</p>
      <p v-if="notice" role="status" class="good">{{ notice }}</p>
    </section>
  </template>
</template>
