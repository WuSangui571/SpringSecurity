package com.sangui.springsecurity.handler;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.sangui.springsecurity.model.TUser;
import com.sangui.springsecurity.result.R;
import com.sangui.springsecurity.util.JwtUtil;
import jakarta.annotation.Resource;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * @Author: sangui
 * @CreateTime: 2025-06-25
 * @Description: 我的成功验证的 Handler
 * @Version: 1.0
 */
@Component
public class MyAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    // Redis 的 key 命名规范：项目名:模块名:功能名[:唯一业务参数]
    public static final String REDIS_TOKEN_KEY = "springsecurity:user:token";

    @Resource
    private RedisTemplate<String,Object> redisTemplate;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // 在这里生成 JWT (token)
        // 获取 user 对象
        TUser tUser = (TUser) authentication.getPrincipal();
        // 转化为 json 对象
        String tUserJson = new ObjectMapper().writeValueAsString(tUser);
        // 生成 JWT
        String jwt = JwtUtil.createToken(tUserJson);

        // 将生成的 JWT 放入 Redis
        redisTemplate.opsForHash().put(REDIS_TOKEN_KEY,tUser.getId().toString(),jwt);

        // 测试一下，怎么把 Redis 的值取出来
        // String redisToken = (String)redisTemplate.opsForHash().get(REDIS_TOKEN_KEY, tUser.getId());
        // System.out.println("redisToken:"+redisToken);


        // 返回的 result 的结果码是 200,信息是登录成功,并返回权限信息
        // 这里将生成的 jwt 返回给前端
        R result = R.ok("登录成功",jwt);
        // 将 result 对象转化为 json 字符串
        String json = new ObjectMapper().writeValueAsString(result);
        // 设置返回的类型和字符集
        response.setContentType("application/json;charset=UTF-8");

        response.getWriter().write(json);
    }
}
