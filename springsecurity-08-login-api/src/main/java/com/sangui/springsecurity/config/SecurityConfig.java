package com.sangui.springsecurity.config;


import com.sangui.springsecurity.filter.CaptchaFilter;
import com.sangui.springsecurity.handler.MyAuthenticationFailHandler;
import com.sangui.springsecurity.handler.MyAuthenticationSuccessHandler;
import com.sangui.springsecurity.handler.MyLogoutSuccessHandler;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

/**
 * @Author: sangui
 * @CreateTime: 2025-06-20
 * @Description: SpringSecurity 的配置文件类
 * @Version: 1.0
 */
@Slf4j
@Configuration
@EnableMethodSecurity()
public class SecurityConfig {
    @Resource
    MyLogoutSuccessHandler myLogoutSuccessHandler;

    @Resource
    MyAuthenticationSuccessHandler myAuthenticationSuccessHandler;

    @Resource
    MyAuthenticationFailHandler myAuthenticationFailHandler;

    @Resource
    CaptchaFilter captchaFilter;

    // 新增 CorsConfigurationSource 对象到我们的容器中，之后在 securityFilterChain 的请求中使用
    @Bean
    public CorsConfigurationSource corsConfigurationSource(){
        // 我们选择基于路径的 CorsConfigurationSource 接口的实现类
        UrlBasedCorsConfigurationSource urlBasedCorsConfigurationSource = new UrlBasedCorsConfigurationSource();

        // 跨域设置
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        // 允许任何来源，
        corsConfiguration.setAllowedOrigins(Arrays.asList("*"));
        // 允许任何请求方法，post,get,put,delete
        corsConfiguration.setAllowedMethods(Arrays.asList("*"));
        // 允许任何的请求头
        corsConfiguration.setAllowedHeaders(Arrays.asList("*"));

        // 注册跨域配置，这里 '/**' 表示任何路径都会匹配（无论这个路径有几层）
        urlBasedCorsConfigurationSource.registerCorsConfiguration("/**",corsConfiguration);

        return urlBasedCorsConfigurationSource;
    }

    // 将 SpringSecurity 中的 BCrypt 加密器引入我们的 IoC 容器之中
    // 相当于 xml 文件中的：<bean id="passwordEncoder" class="org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder"/>
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // 配置 SpringSecurity 框架的一些行为（配置我们的登录页，不使用框架默认的登录页）
    // 但是当你配置了 SecurityFilterChain 这个类之后，SpringSecurity 框架的某些行为就弄丢了（失效了），此时你需要加回来
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity,CorsConfigurationSource corsConfigurationSource) throws Exception {
        // 一般不会这么 new 一个对象的
        // return new DefaultSecurityFilterChain();

        return httpSecurity
                // 配置自己的登录页
                .formLogin((formLogin) -> {
                    // 定制登录页 (Thymeleaf 页面)
                    formLogin
                            .loginProcessingUrl("/user/login")
                            // .loginPage("/toLogin")
                            // 后续测试发现的小 bug,要加上这一行，不然登录成功之后系统不知道跳转到哪一个页面，只能跳转到错误页面
                            // .defaultSuccessUrl("/", true);
                            // 在这里加入我们的成功的 Handler
                            .successHandler(myAuthenticationSuccessHandler)
                            .failureHandler(myAuthenticationFailHandler);

                })

                // 退出登录
                .logout((logout) ->{
                    logout.logoutUrl("/user/logout")
                            // 退出成功后执行的 handler
                            .logoutSuccessHandler(myLogoutSuccessHandler);
                })

                // 把所有接口都会进行登录状态检查的默认行为，再加回来
                .authorizeHttpRequests((authorizeHttpRequests) -> {
                    // 任何对后端接口的请求，都需要认证（登录）后才能访问
                    authorizeHttpRequests
                            // 特殊情况设置，"/toLogin"页面允许访问
                            //.requestMatchers("/toLogin","/common/captcha").permitAll()
                            .anyRequest().authenticated();
                })

                // 将我们的验证码过滤器，放在这个接受用户账号密码的 filter 之前
                //.addFilterBefore(captchaFilter, UsernamePasswordAuthenticationFilter.class)

                .csrf((csrf) ->{
                    // 禁用 csrf 跨站请求伪造。禁用之后，肯定不安全，有网络攻击的危险，后续加入 jwt 是可以防御的
                    csrf.disable();
                })
                .cors((cors) ->{
                    // 允许前端跨域访问
                    cors.configurationSource(corsConfigurationSource);
                })

                // 禁用 session、cookie 机制（因为我们是前后端分离项目的开发）
                .sessionManagement((sessionManagement) -> {
                    // 使用无状态策略
                    sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                })

                .build();
    }



}
