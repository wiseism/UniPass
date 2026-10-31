package com.unipass.server;

import com.unipass.password.PasswordChangeService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.*;

@Configuration
@EnableScheduling
@ConditionalOnProperty(name = "unipass.jobs.enabled", havingValue = "true", matchIfMissing = true)
public class RecoveryJobs {
  private final RecoveryMailWorker mail;
  private final PasswordChangeService passwords;
  private final RedisSecurityState security;
  private final MfaLifecycleService factors;
  private final BackchannelLogoutWorker logout;
  private final SyncTaskWorker sync;
  private final FeishuService feishu;
  private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(RecoveryJobs.class);

  public RecoveryJobs(
      RecoveryMailWorker mail,
      PasswordChangeService passwords,
      RedisSecurityState security,
      MfaLifecycleService factors,
      BackchannelLogoutWorker logout,
      SyncTaskWorker sync,
      FeishuService feishu) {
    this.mail = mail;
    this.passwords = passwords;
    this.security = security;
    this.factors = factors;
    this.logout = logout;
    this.sync = sync;
    this.feishu = feishu;
  }

  @Scheduled(fixedDelayString = "${unipass.jobs.feishu-cleanup-delay-ms:60000}")
  void feishu() {
    try {
      feishu.cleanup();
    } catch (RuntimeException e) {
      LOG.warn("Feishu flow cleanup unavailable");
    }
  }

  @Scheduled(fixedDelayString = "${unipass.jobs.sync-delay-ms:1000}")
  void sync() {
    try {
      sync.runOnce();
    } catch (RuntimeException e) {
      LOG.warn("Sync delivery storage unavailable");
    }
  }

  @Scheduled(fixedDelayString = "${unipass.jobs.logout-delay-ms:1000}")
  void logout() {
    try {
      logout.runOnce();
    } catch (RuntimeException e) {
      LOG.warn("Back-channel logout delivery unavailable");
    }
  }

  @Scheduled(fixedDelayString = "${unipass.jobs.security-delay-ms:1000}")
  void security() {
    try {
      security.recoverIfNeeded();
    } catch (RuntimeException e) {
      LOG.warn("Redis authentication recovery unavailable");
    }
  }

  @Scheduled(fixedDelayString = "${unipass.jobs.recovery-delay-ms:5000}")
  void mail() {
    try {
      mail.runOnce();
    } catch (RuntimeException e) {
      LOG.warn("Recovery mail worker state unavailable");
    }
  }

  @Scheduled(fixedDelayString = "${unipass.jobs.recovery-delay-ms:5000}")
  void abandoned() {
    try {
      passwords.markAbandonedUnknown();
    } catch (RuntimeException e) {
      LOG.warn("Password recovery scan unavailable");
    }
    try {
      factors.expire();
    } catch (RuntimeException e) {
      LOG.warn("Factor expiration scan unavailable");
    }
  }
}
