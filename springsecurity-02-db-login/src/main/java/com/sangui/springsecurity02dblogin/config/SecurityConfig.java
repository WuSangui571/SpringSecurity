package com.sangui.springsecurity02dblogin.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @Author: sangui
 * @CreateTime: 2025-06-20
 * @Description: SpringSecurity 的配置文件类
 * @Version: 1.0
 */
@Configuration
public class SecurityConfig {
    // 将 SpringSecurity 中的 BCrypt 加密器引入我们的 IoC 容器之中
    // 相当于 xml 文件中的：<bean id="passwordEncoder" class="org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder"/>
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
