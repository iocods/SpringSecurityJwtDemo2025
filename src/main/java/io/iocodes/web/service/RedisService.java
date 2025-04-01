package io.iocodes.web.service;


import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import java.util.concurrent.TimeUnit;

@Service
public class RedisService {

    private final StringRedisTemplate redisTemplate;

    public RedisService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    // Store data with a custom TTL
    public void setTokenWithTTL(String key, String value, long ttl, TimeUnit timeUnit) {
        redisTemplate.opsForValue().set(key, value, ttl, timeUnit);
    }

    // check if token exists in the database
    public boolean hasToken(String token) {
        return redisTemplate.hasKey(token);
    }
}

