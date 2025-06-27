package com.sangui.springsecurity.model;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;
import java.util.Collection;
import java.util.Date;
import java.util.List;

/**
 * 用户表
 * t_user
 * @author sangui
 */
@Data
public class TUser implements Serializable, UserDetails {
    /**
     * 单独添加的用户权限标识符（权限 code） List
     * 且该字段不希望能够 json 返回前端，添加 @JsonIgnore 注解
     */
    @JsonIgnore
    private List<TPermission> tPermissionList;

    // 删掉之前的基于角色的权限管理字段
//    /**
//     * 单独添加的用户权限 List
//     * 且该字段不希望能够 json 返回前端，添加 @JsonIgnore 注解
//     */
//    @JsonIgnore
//    private List<TRole> tRoleList;

    /**
     * 在这里放入我们的权限 code
     * @return 用户权限集合
     */
    @JsonIgnore
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }

    @JsonIgnore
    @Override
    public String getPassword() {
        // 返回我们的自己字段里的密码
        return this.loginPwd;
    }

    @JsonIgnore
    @Override
    public String getUsername() {
        // 返回我们的自己字段里的账户名
        return this.loginAct;
    }

    // 下面四个是非必要字段，不实现这四个方法，默认都不过期，即都是 true
    @JsonIgnore
    @Override
    public boolean isAccountNonExpired() {
        return this.accountNoExpired == 1;
    }

    @JsonIgnore
    @Override
    public boolean isAccountNonLocked() {
        return this.accountNoLocked == 1;
    }

    @JsonIgnore
    @Override
    public boolean isCredentialsNonExpired() {
        return this.credentialsNoExpired == 1;
    }

    @JsonIgnore
    @Override
    public boolean isEnabled() {
        return this.accountEnabled == 1;
    }

    /**
     * 主键，自动增长，用户ID
     */
    private Integer id;

    /**
     * 登录账号
     */
    private String loginAct;

    /**
     * 登录密码
     */
    private String loginPwd;

    /**
     * 用户姓名
     */
    private String name;

    /**
     * 用户手机
     */
    private String phone;

    /**
     * 用户邮箱
     */
    private String email;

    /**
     * 账户是否没有过期，0已过期 1正常
     */
    private Integer accountNoExpired;

    /**
     * 密码是否没有过期，0已过期 1正常
     */
    private Integer credentialsNoExpired;

    /**
     * 账号是否没有锁定，0已锁定 1正常
     */
    private Integer accountNoLocked;

    /**
     * 账号是否启用，0禁用 1启用
     */
    private Integer accountEnabled;

    /**
     * 创建时间
     */
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss",timezone = "GMT+8")
    private Date createTime;

    /**
     * 创建人
     */
    private Integer createBy;

    /**
     * 编辑时间
     */
    private Date editTime;

    /**
     * 编辑人
     */
    private Integer editBy;

    /**
     * 最近登录时间
     */
    private Date lastLoginTime;

    private static final long serialVersionUID = 1L;
}