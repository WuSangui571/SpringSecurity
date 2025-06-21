package com.sangui.springsecurity.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;

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

    // 配置 SpringSecurity 框架的一些行为（配置我们的登录页，不使用框架默认的登录页）
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        // 一般不会这么 new 一个对象的
        // return new DefaultSecurityFilterChain();


        return httpSecurity
                // 配置自己的登录页
                .formLogin((formLogin) ->{
                    // 定制登录页 (Thymeleaf 页面)
                    // formLogin.loginPage("/login.html");
                })

                .build();
    }
}
