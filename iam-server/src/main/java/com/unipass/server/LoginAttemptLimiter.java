package com.unipass.server;

import java.util.*;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.security.authentication.*;
import org.springframework.stereotype.Service;

/** Redis outage denies authentication; counters contain only keyed identity digests. */
@Service
public class LoginAttemptLimiter {
  private final StringRedisTemplate redis;
  private final DefaultRedisScript<Long> failure =
      new DefaultRedisScript<>(
          """
        local a=redis.call('INCR',KEYS[1]); if a==1 then redis.call('EXPIRE',KEYS[1],1800) end
        if a>=5 then redis.call('SET',KEYS[2],'1','EX',1800) end
        local ip=redis.call('INCR',KEYS[3]); if ip==1 then redis.call('EXPIRE',KEYS[3],60) end
        if ip>=20 then redis.call('SET',KEYS[4],'1','EX',600) end
        return a
        """,
          Long.class);

  public LoginAttemptLimiter(StringRedisTemplate redis) {
    this.redis = redis;
  }

  private static List<String> keys(String employee, String ip) {
    String a = "unipass:login:account:" + DigestAuthorizationService.digest(employee);
    String i = "unipass:login:ip:" + DigestAuthorizationService.digest(ip);
    return List.of(a, a + ":locked", i, i + ":locked");
  }

  public void check(String employee, String ip) {
    try {
      var keys = keys(employee, ip);
      var locks = redis.opsForValue().multiGet(List.of(keys.get(1), keys.get(3)));
      if (locks != null && locks.stream().anyMatch(Objects::nonNull))
        throw new LockedException("Authentication temporarily unavailable");
    } catch (LockedException e) {
      throw e;
    } catch (RuntimeException e) {
      throw new AuthenticationServiceException("Authentication state unavailable");
    }
  }

  public void failed(String employee, String ip) {
    try {
      redis.execute(failure, keys(employee, ip));
    } catch (RuntimeException e) {
      throw new AuthenticationServiceException("Authentication state unavailable");
    }
  }

  public void succeeded(String employee, String ip) {
    check(employee, ip);
    try {
      redis.delete(keys(employee, ip).get(0));
    } catch (RuntimeException e) {
      throw new AuthenticationServiceException("Authentication state unavailable");
    }
  }
}
