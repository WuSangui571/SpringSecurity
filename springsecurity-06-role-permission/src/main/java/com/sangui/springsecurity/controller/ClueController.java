package com.sangui.springsecurity.controller;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * @Author: sangui
 * @CreateTime: 2025-06-24
 * @Description: 线索的 Controller 控制器
 * @Version: 1.0
 */
@RestController
public class ClueController {
    /*
     * 举例，用户 id 为 3 的用户，他叫 zhangqi，拥有以下权限：
     * 线索管理
     * 线索管理
     * 线索管理-列表
     * 线索管理-录入
     * 线索管理-编辑
     * 线索管理-查看
     *
     * 没有以下权限：
     * 线索管理-删除
     * 线索管理-导出
     */

    // 这个方法的权限注解啥也不加，即没有权限验证
    @RequestMapping(value = "/api/index",method = RequestMethod.GET)
    public String index(){
        return "Index Page !";
    }

    @PreAuthorize("hasAuthority('saler')")
    @RequestMapping(value = "/api/clue/menu",method = RequestMethod.GET)
    public String clueMenu(){
        return "clueMenu";
    }

    @PreAuthorize("hasAuthority('saler')")
    @RequestMapping(value = "/api/clue/menu/child",method = RequestMethod.GET)
    public String clueMenuChild(){
        return "clueMenuChild";
    }

    @PreAuthorize("hasAuthority('saler')")
    @RequestMapping(value = "/api/clue/list",method = RequestMethod.GET)
    public String clueList(){
        return "clueList";
    }

    @PreAuthorize("hasAuthority('saler')")
    @RequestMapping(value = "/api/clue/input",method = RequestMethod.GET)
    public String clueInput(){
        return "clueInput";
    }

    @PreAuthorize("hasAuthority('saler')")
    @RequestMapping(value = "/api/clue/edit",method = RequestMethod.GET)
    public String clueEdit(){
        return "clueEdit";
    }

    @PreAuthorize("hasAuthority('saler')")
    @RequestMapping(value = "/api/clue/view",method = RequestMethod.GET)
    public String clueView(){
        return "clueView";
    }

    @PreAuthorize("hasAuthority('admin')")
    @RequestMapping(value = "/api/clue/del",method = RequestMethod.GET)
    public String clueDel(){
        return "clueDel";
    }

    // hasAnyRole注解，代表只有这些角色的其中一个就能通过
    @PreAuthorize("hasAnyAuthority('admin','manager')")
    @RequestMapping(value = "/api/clue/export",method = RequestMethod.GET)
    public String clueExport(){
        return "clueExport";
    }
}
