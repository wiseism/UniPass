package com.unipass.server;

import java.util.List;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class RecoveryRateLimiter {
  private final StringRedisTemplate redis;
  private final DefaultRedisScript<Long> counter =
      new DefaultRedisScript<>(
          """
        local a=redis.call('INCR',KEYS[1]); if a==1 then redis.call('EXPIRE',KEYS[1],900) end
        local i=redis.call('INCR',KEYS[2]); if i==1 then redis.call('EXPIRE',KEYS[2],900) end
        if a>5 or i>20 then return 0 end
        return 1
        """,
          Long.class);

  public RecoveryRateLimiter(StringRedisTemplate redis) {
    this.redis = redis;
  }

  public boolean allow(String employee, String ip) {
    try {
      return Long.valueOf(1)
          .equals(
              redis.execute(
                  counter,
                  List.of(
                      "unipass:reset:account:" + DigestAuthorizationService.digest(employee),
                      "unipass:reset:ip:" + DigestAuthorizationService.digest(ip))));
    } catch (RuntimeException e) {
      throw new ResponseStatusException(
          HttpStatus.SERVICE_UNAVAILABLE, "Recovery state unavailable");
    }
  }
}
