package com.sangui.springsecurity.controller;


import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * @Author: sangui
 * @CreateTime: 2025-06-20
 * @Description: User 的控制器Controller
 * @Version: 1.0
 */
@Controller
public class UserController {
    // 若用户已登录，会访问 http://localhost:8080/ 的欢迎界面
    // 若用户未登录，会访问 http://localhost:8080/login 的自动登录界面
    @RequestMapping(value = "/",method = RequestMethod.GET)
    @ResponseBody
    public String index(){
        return "Welcome to Spring Security";
    }
    @RequestMapping(value = "/toLogin",method = RequestMethod.GET)
    public String toLogin(){
        return "login";
    }
}
