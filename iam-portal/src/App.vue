<script setup lang="ts">
import { ref } from 'vue'
import type { Component } from 'vue'
import { get, logout, message } from './api'
import LoginPage from './pages/LoginPage.vue'
import OverviewPage from './pages/OverviewPage.vue'
import MfaPage from './pages/MfaPage.vue'
import PasswordPage from './pages/PasswordPage.vue'
import ResetPage from './pages/ResetPage.vue'
import SessionsPage from './pages/SessionsPage.vue'
import FactorsPage from './pages/FactorsPage.vue'
import BindingPage from './pages/BindingPage.vue'
import AdminPage from './pages/AdminPage.vue'
const path = window.location.pathname; const publicPage = path === '/login' || path === '/reset'
const pages: Record<string, Component> = { '/login': LoginPage, '/reset': ResetPage, '/portal/': OverviewPage, '/portal/mfa': MfaPage, '/portal/password': PasswordPage, '/portal/sessions': SessionsPage, '/portal/factors': FactorsPage, '/portal/binding': BindingPage, '/portal/admin': AdminPage }
const links = ref([{ path: '/portal/', name: '账户概览' }, { path: '/portal/password', name: '账户密码' }, { path: '/portal/mfa', name: '身份验证' }, { path: '/portal/factors', name: '验证器' }, { path: '/portal/sessions', name: '登录管理' }, { path: '/portal/binding', name: '飞书绑定' }])
// The console entry is only surfaced to operators; the server re-checks the role.
if (!publicPage) void get<{ roles?: string[] }>('/api/session/me').then(value => {
  if (value.roles?.includes('ROLE_SYSTEM_ADMIN')) links.value = [...links.value, { path: '/portal/admin', name: '管理控制台' }]
}).catch(() => { /* portal pages handle their own 401 recovery */ })
const error = ref(''); const busy = ref(false); const flowError = new URLSearchParams(window.location.search).has('flow_error')
async function exit() { if (busy.value) return; busy.value = true; error.value = ''; try { await logout() } catch (failure) { error.value = message(failure); busy.value = false } }
</script>
<template>
  <a class="skip-link" href="#main">跳转到主要内容</a>
  <div :class="publicPage ? 'public-shell' : 'shell'">
    <aside :class="publicPage ? 'public-brand' : 'sidebar'"><a class="brand" href="/portal/" aria-label="UniPass 账户首页"><span class="brand-mark" aria-hidden="true">U</span><span>UniPass<small>企业账户中心</small></span></a>
      <template v-if="!publicPage"><nav aria-label="账户导航"><a v-for="link in links" :key="link.path" :href="link.path" :aria-current="path === link.path ? 'page' : undefined">{{ link.name }}</a></nav><button class="logout secondary" :disabled="busy" @click="exit">{{ busy ? '正在退出…' : '退出所有登录' }}</button></template>
    </aside>
    <main id="main" tabindex="-1"><p v-if="error" class="error" role="alert">{{ error }}</p><p v-if="flowError" class="error" role="alert">原应用请求已失效，请从应用重新发起登录。</p><component :is="pages[path]" v-if="pages[path]" /><section v-else class="card"><h1>页面不可用</h1><a href="/portal/">返回账户首页</a></section></main>
  </div>
</template>
