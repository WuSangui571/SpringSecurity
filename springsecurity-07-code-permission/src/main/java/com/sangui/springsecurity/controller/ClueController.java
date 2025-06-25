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
        线索管理-列表 -> clue:list
        线索管理-录入 -> clue:add
        线索管理-编辑 -> clue:edit
        线索管理-查看 -> clue:view
        线索管理-导入 -> clue:import
     */

    // 这个方法的权限注解啥也不加，即没有权限验证
    @RequestMapping(value = "/api/clue/index",method = RequestMethod.GET)
    public String index(){
        return "Index Page !";
    }

    @PreAuthorize("hasAuthority('clue:list')")
    @RequestMapping(value = "/api/clue/list",method = RequestMethod.GET)
    public String clueList(){
        return "clueList";
    }

    @PreAuthorize("hasAuthority('clue:add')")
    @RequestMapping(value = "/api/clue/add",method = RequestMethod.GET)
    public String clueAdd(){
        return "clueAdd";
    }

    @PreAuthorize("hasAuthority('clue:edit')")
    @RequestMapping(value = "/api/clue/edit",method = RequestMethod.GET)
    public String clueEdit(){
        return "clueEdit";
    }

    @PreAuthorize("hasAuthority('clue:view')")
    @RequestMapping(value = "/api/clue/view",method = RequestMethod.GET)
    public String clueView(){
        return "clueView";
    }

    @PreAuthorize("hasAuthority('clue:import')")
    @RequestMapping(value = "/api/clue/import",method = RequestMethod.GET)
    public String clueImport(){
        return "clueImport";
    }

    // 这是该用户没有的权限 code
    @PreAuthorize("hasAuthority('clue:del')")
    @RequestMapping(value = "/api/clue/del",method = RequestMethod.GET)
    public String clueDel(){
        return "clueDel";
    }

    // hasAnyRole注解，代表只有这些 code 的其中一个就能通过
    @PreAuthorize("hasAnyAuthority('clue:xxx','clue:yyy')")
    @RequestMapping(value = "/api/clue/xxyy",method = RequestMethod.GET)
    public String clueExport(){
        return "clueExport";
    }
}
