package com.sangui.springsecurity02dblogin.mapper;

import com.sangui.springsecurity02dblogin.model.TUser;

/**
 * @author sangui
 */
public interface TUserMapper {
    int deleteByPrimaryKey(Integer id);

    int insert(TUser record);

    int insertSelective(TUser record);

    TUser selectByPrimaryKey(Integer id);

    int updateByPrimaryKeySelective(TUser record);

    int updateByPrimaryKey(TUser record);

    TUser selectByLoginAct(String loginAct);
}