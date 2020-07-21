package com.lg.auth.controller;


import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.lg.auth.entity.Role;
import com.lg.auth.entity.RoleMenu;
import com.lg.auth.entity.RoleVo;
import com.lg.auth.entity.UserRole;
import com.lg.auth.service.IRoleMenuService;
import com.lg.auth.service.IRoleService;
import com.lg.auth.service.IUserRoleService;
import com.lg.common.pojo.ResponseResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * <p>
 *  前端控制器
 * </p>
 *
 * @author zhanggm
 * @since 2020-06-03
 */
@RestController
@RequestMapping("/role")
public class RoleController {

    @Autowired
    private IRoleService iRoleService;

    @Autowired
    private IRoleMenuService iRoleMenuService;

    @Autowired
    private IUserRoleService iUserRoleService;

    /**
     * 列表分页接口
     * @param role
     * @param page
     * @return
     */
    @GetMapping("list")
    public ResponseResult list(Role role, Page page){
        //查询条件
        QueryWrapper queryWrapper = new QueryWrapper();
        if(role.getName()!=null){
            queryWrapper.like("name",role.getName());
        }
        //查询数据
        IPage<Role> pageInfo = iRoleService.page(page,queryWrapper);
        return ResponseResult.success(pageInfo);
    }

    /**
     * 根据角色Id，查询菜单IdList
     * @return
     */
    @GetMapping("getMenuIdListByRoleId")
    public ResponseResult getMenuIdListByRoleId(Integer roleId){
        QueryWrapper queryWrapper = new QueryWrapper();
        queryWrapper.eq("rid",roleId);
        List<RoleMenu> roleMenuList = iRoleMenuService.list(queryWrapper);
        List<Integer> menuIdList = roleMenuList.stream().map(rm -> rm.getMid()).collect(Collectors.toList());
        return ResponseResult.success(menuIdList);
    }

    /**
     * 绑定菜单数据
     * @param roleVo
     * @return
     */
    @PostMapping("saveRoleMenuData")
    public ResponseResult saveRoleMenuData(@RequestBody RoleVo roleVo){
        //删除关系表数据
        QueryWrapper queryWrapper = new QueryWrapper();
        queryWrapper.eq("rid",roleVo.getRoleId());
        iRoleMenuService.remove(queryWrapper);
        List<Integer> menuIdList = roleVo.getMenuIdList();
        //批量保存
        List<RoleMenu> roleMenuList = new ArrayList<>();
        menuIdList.forEach(menuId->{
            RoleMenu roleMenu = new RoleMenu();
            roleMenu.setRid(roleVo.getRoleId());
            roleMenu.setMid(menuId);
            roleMenuList.add(roleMenu);
        });
        iRoleMenuService.saveBatch(roleMenuList);
        return ResponseResult.success();
    }


    /**
     * 保存：新增、修改
     * @param role
     * @return
     */
    @PostMapping("save")
    public ResponseResult save(@RequestBody Role role){
        iRoleService.saveOrUpdate(role);
        return ResponseResult.success(null);
    }

    /**
     * 查询所有的角色
     * @return
     */
    @GetMapping("listAll")
    public ResponseResult listAll(){
        return ResponseResult.success(iRoleService.list());
    }
}
