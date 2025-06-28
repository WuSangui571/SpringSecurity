package com.sangui.springsecurity.handler;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.sangui.springsecurity.model.TUser;
import com.sangui.springsecurity.result.R;
import jakarta.annotation.Resource;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * @Author: sangui
 * @CreateTime: 2025-06-25
 * @Description: 我的成功验证的 Handler
 * @Version: 1.0
 */
@Component
public class MyLogoutSuccessHandler implements LogoutSuccessHandler {
    @Resource
    private RedisTemplate<String,Object> redisTemplate;

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // 退出成功后在 Redis 中删除对应的 tUser 的 id 的数据
        TUser tUser = (TUser) authentication.getPrincipal();
        redisTemplate.opsForHash().delete(MyAuthenticationSuccessHandler.REDIS_TOKEN_KEY,tUser.getId().toString());

        // 返回的 result 的结果码是 200,信息是登录成功,并返回权限信息
        R result = R.ok("退出成功",authentication);

        // 将 result 对象转化为 json 字符串
        String json = new ObjectMapper().writeValueAsString(result);
        // 设置返回的类型和字符集
        response.setContentType("application/json;charset=UTF-8");

        response.getWriter().write(json);
    }
}
