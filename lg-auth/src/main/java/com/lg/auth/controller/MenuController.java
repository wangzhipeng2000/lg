package com.lg.auth.controller;


import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.lg.auth.entity.Menu;
import com.lg.auth.entity.MenuVo;
import com.lg.auth.feign.UserClient;
import com.lg.auth.service.IMenuService;
import com.lg.common.pojo.ResponseResult;
import com.lg.user.api.pojo.UserVo;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.List;

/**
 * <p>
 *  前端控制器
 * </p>
 *
 * @author zhanggm
 * @since 2020-06-03
 */
@RestController
@RequestMapping("/menu")
public class MenuController {

    @Autowired
    private IMenuService iMenuService;

    @Autowired
    private UserClient userClient;

    @Autowired
    private RedisTemplate redisTemplate;

    @GetMapping("list")
    public ResponseResult list(MenuVo menuVo, Page page){
        IPage<MenuVo> pageInfo = iMenuService.getPageInfo(menuVo,page);
        return ResponseResult.success(pageInfo);
    }

    /**
     * 根据登录名称，查询用户菜单
     * @return
     */
    @GetMapping("getMenuVoListByUsername")
    public ResponseResult getMenuVoListByUsername(HttpServletRequest request){
        System.out.println(request.getHeader("token"));
        String token = request.getHeader("token");
        UserVo loginUserInfo = getLoginUserInfo(token);
        List<MenuVo> menuList = iMenuService.getMenuVoListByUsername(loginUserInfo.getUsername());
        return ResponseResult.success(menuList);
    }

    /**
     * 获取当前登录的用户信息
     * @param token
     * @return
     */
    private UserVo getLoginUserInfo(@RequestParam("token") String token){
        UserVo user = (UserVo) redisTemplate.opsForValue().get(token);
        UserVo userVo = new UserVo();
        BeanUtils.copyProperties(user,userVo);
        return userVo;
    }

    /**
     * 根据pid查询菜单列表
     * @param parentId
     * @return
     */
    @GetMapping("getMenuListByParentId")
    public ResponseResult getMenuListByParentId(Integer parentId){
        QueryWrapper queryWrapper = new QueryWrapper();
        queryWrapper.eq("parentId",parentId);
        List list = iMenuService.list(queryWrapper);
        return ResponseResult.success(list);
    }

    @PostMapping("save")
    public ResponseResult save(@RequestBody Menu menu){
        if(menu.getId()==null){
            menu.setCreateTime(LocalDateTime.now());
        }
        boolean b = iMenuService.saveOrUpdate(menu);
        return ResponseResult.success(b);
    }
}
