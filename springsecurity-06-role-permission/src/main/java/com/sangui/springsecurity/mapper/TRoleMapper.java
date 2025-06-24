package com.sangui.springsecurity.mapper;

import com.sangui.springsecurity.model.TRole;

import java.util.List;

/**
 * @author root
 */
public interface TRoleMapper {
    int deleteByPrimaryKey(Integer id);

    int insert(TRole record);

    int insertSelective(TRole record);

    TRole selectByPrimaryKey(Integer id);

    int updateByPrimaryKeySelective(TRole record);

    int updateByPrimaryKey(TRole record);

    List<TRole> selectByUserId(Integer userId);
}