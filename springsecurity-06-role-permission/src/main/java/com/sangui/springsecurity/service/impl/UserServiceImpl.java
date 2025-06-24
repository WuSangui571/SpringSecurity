package com.sangui.springsecurity.service.impl;


import com.sangui.springsecurity.mapper.TRoleMapper;
import com.sangui.springsecurity.mapper.TUserMapper;
import com.sangui.springsecurity.model.TRole;
import com.sangui.springsecurity.model.TUser;
import com.sangui.springsecurity.service.UserService;
import jakarta.annotation.Resource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * @Author: sangui
 * @CreateTime: 2025-06-20
 * @Description: UserService 实现类
 * @Version: 1.0
 */
@Service
public class UserServiceImpl implements UserService {
    @Resource
    private TUserMapper tUserMapper;

    @Resource
    private TRoleMapper tRoleMapper;

    /**
     * 该方法会在登录的时候会被 SpringSecurity 调用
     * @param username the username identifying the user whose data is required.
     * @return SpringSecurity 框架里面的 user 对象
     * @throws UsernameNotFoundException 若找不到这个 tUser,则抛出 SpringSecurity 提供的登录账号不存在异常，
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 查询页面上传过来的用户名（username）是否存在与数据库中，这个用户名（username）是前端用户输入的
        TUser tUser = tUserMapper.selectByLoginAct(username);

        // 若找不到这个 tUser,则抛出 SpringSecurity 提供的异常
        if (tUser == null) {
            throw new UsernameNotFoundException("登录账号不存在");
        }

        // 现在，我们就不需要以下的代码了！
//        // 构建一个 SpringSecurity 框架里面的 user 对象来返回
//        UserDetails userDetails = User.builder()
//                .username(tUser.getLoginAct())
//                .password(tUser.getLoginPwd())
//                // 权限先设置为空
//                .authorities(AuthorityUtils.NO_AUTHORITIES)
//                // 设置账户失效
//                // .credentialsExpired(true)
//                .build();

        // 在此处查询用户的角色信息列表（一个用户可能有多个角色）
        List<TRole> tRoleList = tRoleMapper.selectByUserId(tUser.getId());
        // 通过 set 方法写入我们的权限列表这个属性
        tUser.setTRoleList(tRoleList);


        // 这里返回我们自己的 tUser 对象
        return tUser;
    }
}
