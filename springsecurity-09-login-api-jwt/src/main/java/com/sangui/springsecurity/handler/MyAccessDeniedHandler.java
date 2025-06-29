package com.sangui.springsecurity.handler;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.sangui.springsecurity.model.TUser;
import com.sangui.springsecurity.result.R;
import jakarta.annotation.Resource;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.AccessDeniedHandler;
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
public class MyAccessDeniedHandler implements AccessDeniedHandler{
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        // 返回的 result 的结果码是 403,信息是登录失败,并返回异常信息
        R result = R.fail(403,"权限不足",null);

        // 将 result 对象转化为 json 字符串
        String json = new ObjectMapper().writeValueAsString(result);
        // 设置返回的类型和字符集
        response.setContentType("application/json;charset=UTF-8");

        response.getWriter().write(json);
    }
}
