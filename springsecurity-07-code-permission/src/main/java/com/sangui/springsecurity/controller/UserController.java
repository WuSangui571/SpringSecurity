package com.sangui.springsecurity.controller;


import com.sangui.springsecurity.util.LoginInfoUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import java.security.Principal;

/**
 * @Author: sangui
 * @CreateTime: 2025-06-20
 * @Description: User 的控制器Controller
 * @Version: 1.0
 */
@Controller
public class UserController {
    // 若用户已登录，会访问 http://localhost:8080/ 的欢迎界面
    // 若用户未登录，会访问 http://localhost:8080/toLogin 的自动登录界面
    @RequestMapping(value = "/",method = RequestMethod.GET)
    @ResponseBody
    public String index(){
        return "Welcome to Spring Security";
    }

    @RequestMapping(value = "/toLogin",method = RequestMethod.GET)
    public String toLogin(){
        return "login";
    }

    // 新增页面路径，访问这个页面，可以获取用户的所有具体信息（也就是用户表中有的字段的信息）
    @RequestMapping(value = "/userInfo",method = RequestMethod.GET)
    @ResponseBody
    public Object userInfo(Principal principal){
        return principal;
    }

    // 新增新的页面路径，这个路径使用的 SpringSecurity 框架提供的 Authentication 接口
    // 今后最常用的就是 Authentication，不会用 Principal 的
    @RequestMapping(value = "/userInfo2",method = RequestMethod.GET)
    @ResponseBody
    public Object userInfo2(Authentication authentication){
        return authentication;
    }


    @RequestMapping(value = "/userInfo3",method = RequestMethod.GET)
    @ResponseBody
    public Object userInfo3(UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken){
        return usernamePasswordAuthenticationToken;
    }

    @RequestMapping(value = "/userInfo4",method = RequestMethod.GET)
    @ResponseBody
    public Object userInfo4(){
        return SecurityContextHolder.getContext().getAuthentication();
    }

    @RequestMapping(value = "/userInfo5",method = RequestMethod.GET)
    @ResponseBody
    public Object userInfo5(){
        return LoginInfoUtil.getCurrentLoginUser();
    }
}
