package com.sangui.springsecurity.util;


import com.sangui.springsecurity.model.TUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * @Author: sangui
 * @CreateTime: 2025-06-22
 * @Description: 登录人信息的工具类
 * @Version: 1.0
 */
public class LoginInfoUtil {
    private LoginInfoUtil(){}
    public static TUser getCurrentLoginUser(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return (TUser) authentication.getPrincipal();
    }
}
