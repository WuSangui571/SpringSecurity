package com.sangui.springsecurity.listener;


import com.sangui.springsecurity.handler.MyAuthenticationSuccessHandler;
import jakarta.annotation.Resource;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextClosedEvent;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

/**
 * @Author: sangui
 * @CreateTime: 2025-06-28
 * @Description: 监听器，服务关闭/重启，删除 Redis 的所有 JWT
 * @Version: 1.0
 */
@Component
public class ShutdownListener implements ApplicationListener<ContextClosedEvent> {
    @Resource
    private RedisTemplate<String,Object> redisTemplate;

    /**
     * 服务关闭/重启，删除 Redis 的所有 JWT
     * @param event the event to respond to
     */
    @Override
    public void onApplicationEvent(ContextClosedEvent event) {
        //System.out.println("应用 is shutting down...");
        // 删除代码
        redisTemplate.delete(MyAuthenticationSuccessHandler.REDIS_TOKEN_KEY);

    }
}
