package com.lg.auth.controller;


import com.alibaba.fastjson.JSON;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.lg.auth.entity.UserRole;
import com.lg.auth.feign.UserClient;
import com.lg.auth.service.IUserRoleService;
import com.lg.common.pojo.ResponseResult;
import com.lg.common.utils.MD5;
import com.lg.user.api.pojo.UserVo;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.concurrent.TimeUnit;
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
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserClient userClient;

    @Autowired
    private RedisTemplate redisTemplate;

    @Autowired
    private IUserRoleService iUserRoleService;

    /**
     * 用户登录接口
     * @param userVo
     * @return
     */
    @PostMapping("login")
    public ResponseResult login(@RequestBody UserVo userVo){
        //验证用户名和密码是否为空
        if(StringUtils.isBlank(userVo.getPassword()) || StringUtils.isBlank(userVo.getPassword())){
            return ResponseResult.error(10000,"用户名或密码不能为空");
        }
        //查询一条用户信息
        UserVo userInfo = userClient.getUserVoByUsername(userVo.getUsername());
        //用户是否停用
        if(!userInfo.getEnabled()){
            return ResponseResult.error(10000,"用户名或密码不能为空");
        }
        //验证密码
        if(userInfo==null || !userInfo.getPassword().equals(userVo.getPassword())){
            return ResponseResult.error(10000,"用户名或密码不能为空");
        }
        //生成token信息 Jwt
        String token = MD5.encryptPassword(JSON.toJSONString(userInfo), System.currentTimeMillis() + "");
        userInfo.setToken(token);
        //把token信息存储到redis,同时存储用户信息
        redisTemplate.opsForValue().set(token,userInfo);
        redisTemplate.expire(token,60, TimeUnit.SECONDS);
        //设置密码为空
        userInfo.setPassword(null);
        userInfo.setUsername(null);
        return ResponseResult.success(userInfo);
    }

    /**
     * 保存用户角色
     * @param userVo
     * @return
     */
    @PostMapping("bindRoles")
    public ResponseResult bindRoles(@RequestBody UserVo userVo){
        //删除角色
        QueryWrapper queryWrapper = new QueryWrapper();
        queryWrapper.eq("uid",userVo.getId());
        iUserRoleService.remove(queryWrapper);
        //添加用户角色
        userVo.getRoleIdList().forEach(roleId->{
            UserRole userRole = new UserRole();
            userRole.setUid(userVo.getId());
            userRole.setRid(roleId);
            iUserRoleService.save(userRole);
        });
        return ResponseResult.success();
    }



    /**
     *  查询用户关联的角色Id
     * @return
     */
    @GetMapping("getRoleIdListByUserId")
    public ResponseResult getRoleIdListByUserId(String userId){
        //查询用户角色
        QueryWrapper queryWrapper = new QueryWrapper();
        queryWrapper.eq("uid",userId);
        List<UserRole> list = iUserRoleService.list(queryWrapper);
        //返回角色Id
        List<Integer> roleIdList = list.stream().map(ur->ur.getRid()).collect(Collectors.toList());
        return ResponseResult.success(roleIdList);
    }



}
