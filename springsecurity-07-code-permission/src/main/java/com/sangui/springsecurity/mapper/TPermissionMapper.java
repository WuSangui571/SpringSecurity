package com.sangui.springsecurity.mapper;

import com.sangui.springsecurity.model.TPermission;

import java.util.List;

/**
 * @author sangui
 */
public interface TPermissionMapper {
    int deleteByPrimaryKey(Integer id);

    int insert(TPermission record);

    int insertSelective(TPermission record);

    TPermission selectByPrimaryKey(Integer id);

    int updateByPrimaryKeySelective(TPermission record);

    int updateByPrimaryKey(TPermission record);

    List<TPermission> selectByUserId(Integer id);
}