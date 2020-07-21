package com.lg.user.api;

import com.lg.user.api.pojo.UserVo;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

public interface UserApi {
    /**
     * 根据token获取当前的用户信息
     * @param token
     * @return
     */
    @GetMapping("/user/getLoginUserInfo")
    public UserVo getLoginUserInfo(@RequestParam("token") String token);

    /**
     * 根据用户名查询用户
     * @param username
     * @return
     */
    @GetMapping("/user/getUserVoByUsername")
    public UserVo getUserVoByUsername(@RequestParam("username") String username);



}
