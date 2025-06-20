package com.sangui.springsecurity.controller;


import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * @Author: sangui
 * @CreateTime: 2025-06-20
 * @Description: User 的控制器
 * @Version: 1.0
 */
@RestController
public class UserController {
    @RequestMapping(value = "/",method = RequestMethod.GET)
    public String index(){
        return "Hello Index";
    }

    @RequestMapping(value = "/hello",method = RequestMethod.GET)
    public String hello(){
        return "Hello Spring Security!";
    }
}
