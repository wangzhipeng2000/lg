package com.lg.auth.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.lg.auth.entity.Menu;
import com.lg.auth.entity.MenuVo;
import com.lg.auth.entity.RoleMenu;
import com.lg.auth.entity.UserRole;
import com.lg.auth.feign.UserClient;
import com.lg.auth.mapper.MenuMapper;
import com.lg.auth.service.IMenuService;
import com.lg.auth.service.IRoleMenuService;
import com.lg.auth.service.IUserRoleService;
import com.lg.user.api.pojo.UserVo;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * <p>
 *  服务实现类
 * </p>
 *
 * @author zhanggm
 * @since 2020-06-03
 */
@Service
public class MenuServiceImpl extends ServiceImpl<MenuMapper, Menu> implements IMenuService {

    @Autowired
    private UserClient userClient;

    @Autowired
    private IUserRoleService iUserRoleService;

    @Autowired
    private IRoleMenuService iRoleMenuService;


    /**
     * 根据登录名称，查询用户菜单
     * @param username
     * @return
     */
    @Override
    public List<MenuVo> getMenuVoListByUsername(String username) {
        //管理员加载所有数据
        if("admin".equals(username)){
            //查询菜单
            List<Menu> allMenuList = this.list();
            //封装一级二级菜单、Menu转MenuVo
            return toMenuVoList(allMenuList);
        }
        //非管理员用户
        List<Menu> userMenuList = getMenuListByUsername(username);
        return toMenuVoList(userMenuList);
    }

    @Override
    public IPage<MenuVo> getPageInfo(MenuVo menuVo, Page page) {
        IPage<MenuVo> menuVoIPage = this.getBaseMapper().selectPageInfo(menuVo, page);
        menuVoIPage.getRecords().forEach(menu->{
            if(menu.getParentId()!=0){
                Menu pMenu = this.getById(menu.getParentId());
                menu.setParentName(pMenu.getName());
            }
        });
        return menuVoIPage;
    }

    /**
     * 根据用户名称，查询菜单数据
     * @param username
     * @return
     */
    private List<Menu> getMenuListByUsername(String username) {
        //根据用户名称查询用户Id
        UserVo user = userClient.getUserVoByUsername(username);
        //查询用户角色
        QueryWrapper queryWrapper = new QueryWrapper();
        queryWrapper.eq("uid",user.getId());
        List<UserRole> userRoles = iUserRoleService.list(queryWrapper);
        List<Integer> roleIdList = userRoles.stream().map(ur -> ur.getRid()).collect(Collectors.toList());
        //根据角色查询用户菜单
        queryWrapper = new QueryWrapper();
        queryWrapper.in("rid",roleIdList);
        List<RoleMenu> roleMenus = iRoleMenuService.list(queryWrapper);
        //如果有二级菜单id，那么菜单列表里面就必须包含一级菜单，才能出树的结果。
        List<Integer> menuIdList = roleMenus.stream().map(rm -> rm.getMid()).collect(Collectors.toList());
        //查询菜单
        return this.listByIds(menuIdList);
    }

    /**
     *  把menuList转为MenuVoList
     * @param allMenuList 查询所有的菜单数据
     * @return
     */
    private List<MenuVo> toMenuVoList(List<Menu> allMenuList){
        List<MenuVo> menuVoList = new ArrayList<>();
        //查询一级菜单
        allMenuList.forEach(menu -> {
            if(menu.getParentId()==0){
                MenuVo menuVo = new MenuVo();
                BeanUtils.copyProperties(menu,menuVo);
                menuVoList.add(menuVo);
                //查询二级菜单
                List<MenuVo> subMenuVoList = new ArrayList<>();
                allMenuList.forEach(subMenu->{
                    if(subMenu.getParentId().intValue()==menu.getId().intValue()){
                        MenuVo subMenuVo = new MenuVo();
                        BeanUtils.copyProperties(subMenu,subMenuVo);
                        subMenuVoList.add(subMenuVo);
                    }
                });
                //设置subMenus在二级菜单
                menuVo.setSubMenus(subMenuVoList);
            }
        });
        return menuVoList;
    }

}
