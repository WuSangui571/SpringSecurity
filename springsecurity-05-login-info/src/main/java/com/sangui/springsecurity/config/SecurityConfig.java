package com.sangui.springsecurity.config;


import com.sangui.springsecurity.filter.CaptchaFilter;
import jakarta.annotation.Resource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * @Author: sangui
 * @CreateTime: 2025-06-20
 * @Description: SpringSecurity 的配置文件类
 * @Version: 1.0
 */
@Configuration
public class SecurityConfig {
    @Resource
    CaptchaFilter captchaFilter;

    // 将 SpringSecurity 中的 BCrypt 加密器引入我们的 IoC 容器之中
    // 相当于 xml 文件中的：<bean id="passwordEncoder" class="org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder"/>
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // 配置 SpringSecurity 框架的一些行为（配置我们的登录页，不使用框架默认的登录页）
    // 但是当你配置了 SecurityFilterChain 这个类之后，SpringSecurity 框架的某些行为就弄丢了（失效了），此时你需要加回来
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        // 一般不会这么 new 一个对象的
        // return new DefaultSecurityFilterChain();

        return httpSecurity
                // 配置自己的登录页
                .formLogin((formLogin) -> {
                    // 定制登录页 (Thymeleaf 页面)
                    formLogin
                            .loginProcessingUrl("/user/login")
                            .loginPage("/toLogin")
                            // 后续测试发现的小 bug,要加上这一行，不然登录成功之后系统不知道跳转到哪一个页面，只能跳转到错误页面
                            .defaultSuccessUrl("/", true);
                })

                // 把所有接口都会进行登录状态检查的默认行为，再加回来
                .authorizeHttpRequests((authorizeHttpRequests) -> {
                    // 任何对后端接口的请求，都需要认证（登录）后才能访问
                    authorizeHttpRequests
                            // 特殊情况设置，"/toLogin"页面允许访问
                            .requestMatchers("/toLogin","/common/captcha").permitAll()
                            .anyRequest().authenticated();
                })

                // 将我们的验证码过滤器，放在这个接受用户账号密码的 filter 之前
                .addFilterBefore(captchaFilter, UsernamePasswordAuthenticationFilter.class)

                .build();
    }



}
