package com.sangui.springsecurity;

import com.sangui.springsecurity.mapper.TRoleMapper;
import com.sangui.springsecurity.model.TRole;
import jakarta.annotation.Resource;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

@SpringBootTest
class PermissionApplicationTests {
    @Resource
    TRoleMapper tRoleMapper;

    @Test
    void testSelectByUserId() {

        List<TRole> tRoleList = tRoleMapper.selectByUserId(1);
        System.out.println(tRoleList);
    }

}
