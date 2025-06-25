package com.sangui.springsecurity.filter;


import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * @Author: sangui
 * @CreateTime: 2025-06-22
 * @Description: 验证码过滤器
 * @Version: 1.0
 */

// 通过情况下，使用过滤器都会考虑到实现 servlet 的 Filter 接口这种方式，
// 但在 Spring 项目中，一般不会以这种方式使用，因为需要强转输入类型的参数，比较麻烦。
//public class CaptchaFilter implements Filter {
//@Override
//    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
//        HttpServletRequest request = (HttpServletRequest) servletRequest;
//        HttpServletResponse response = (HttpServletResponse) servletResponse;
//    }
//}

// 我们更加倾向于选择继承 OncePerRequestFilter 类实现
// 继承这个抽象类，实际上也是在间接实现 servlet 的 Filter 接口，只不过继承这种方式不用转型，更加方便
@Component
public class CaptchaFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String captchaFromFront = request.getParameter("captcha");


        // 如果是登录请求，就验证，否则不需要验证
        String requestURI = request.getRequestURI();
        if (!requestURI.equals("/user/login")){
            filterChain.doFilter(request, response);
            return;
        }
        if (!StringUtils.hasText(captchaFromFront)){
            // 前端传的验证码为空，验证未通过
            response.sendRedirect("/");
        }else if (!captchaFromFront.equalsIgnoreCase(request.getSession().getAttribute("captcha").toString())){
            // 两端验证码不相等，验证不通过
            response.sendRedirect("/");
        }else {
            // 通过！
            filterChain.doFilter(request, response);
        }
    }
}
