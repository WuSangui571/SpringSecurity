package com.sangui.springsecurity.filter;


import com.auth0.jwt.exceptions.JWTDecodeException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sangui.springsecurity.config.SecurityConfig;
import com.sangui.springsecurity.handler.MyAuthenticationSuccessHandler;
import com.sangui.springsecurity.model.TUser;
import com.sangui.springsecurity.result.R;
import com.sangui.springsecurity.util.JwtUtil;
import jakarta.annotation.Resource;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * @Author: sangui
 * @CreateTime: 2025-06-28
 * @Description: 验证 JWT 的过滤器
 * @Version: 1.0
 */
@Component
public class JwtFilter extends OncePerRequestFilter {
    @Resource
    private RedisTemplate<String,Object> redisTemplate;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        response.setContentType("application/json;charset=UTF-8");

        // 登录接口不需要进行验证，直接通过
        String requestUri = request.getRequestURI();
        if ("/user/login".equals(requestUri)) {
            filterChain.doFilter(request, response);
        }else {
            // 获取请求头的 JWT
            String jwt = request.getHeader("jwt");
            // 开始验证 JWT
            // 若 JWT 没有值
            if (!StringUtils.hasLength(jwt)) {
                R result = new R(901,"请求 jwt 为空！",null);
                String json = new ObjectMapper().writeValueAsString(result);
                response.getWriter().write(json);

            }else {
                //  JWT 是否被篡改过、
                boolean flag = true;
                try {
                    flag = !JwtUtil.verifyToken(jwt);
                }catch (Exception e){
                    e.printStackTrace();
                }
                if (flag) {
                    R result = new R(902,"请求 jwt 非法！",null);
                    String json = new ObjectMapper().writeValueAsString(result);
                    response.getWriter().write(json);
                } else {
                    // 获取 tUserId
                    String tUserJson = JwtUtil.parseToken(jwt);
                    TUser tUser = new ObjectMapper().readValue(tUserJson, TUser.class);
                    System.out.println(tUser);
                    Integer tUserId = tUser.getId();

                    // 拿 Redis 中的 JWT
                    String redisJwt = (String) redisTemplate.opsForHash().get(MyAuthenticationSuccessHandler.REDIS_TOKEN_KEY,tUserId.toString());
                    // 若前台提供的 JWT 与 Redis 中的 JWT 不匹配
                    if (!jwt.equals(redisJwt)) {
                        R result = new R(903,"请求 jwt 不匹配！",null);
                        String json = new ObjectMapper().writeValueAsString(result);
                        response.getWriter().write(json);
                    }else {
                        // 验证通过！
                        // 将我们的信息传入 SpringSecurity 的上下文里。放入 Authentication 的一个实现类：UsernamePasswordAuthenticationToken
                        // 这一步很重要，如果不放入，即使你通过了这个 JWT 过滤器验证，也会被之后 SpringSecurity 框架后续别的过滤器过滤为匿名请求
                        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(tUser, null, AuthorityUtils.NO_AUTHORITIES));
                        filterChain.doFilter(request, response);
                    }
                }
            }
        }
    }
}
