package com.lg.user.controller;



import com.lg.common.pojo.ResponseResult;
import com.lg.user.api.pojo.UserVo;
import com.lg.user.dao.UserDao;
import com.lg.user.entity.User;
import com.lg.user.service.UserService;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.web.bind.annotation.*;

import java.util.concurrent.TimeUnit;

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
    private UserService userService;

    @Autowired
    private UserDao userDao;

    /**
     * 用户分页列表接口
     * @param
     * @return
     */
    @GetMapping("list")
    public ResponseResult list(User user,Integer current,Integer size){
        Page<User> pageInfo = userService.getPageInfo(user,current,size);
        return ResponseResult.success(pageInfo);
    }

    /**
     * 保存（新增或修改）
     * @param user
     * @return
     */
    @PostMapping("save")
    public ResponseResult save(@RequestBody  User user){
        //创建用户时，设置默认密码
        if(user.getId()==null){
            user.setPassword("123456");
        }
        //保存用户信息
        User save = userDao.save(user);
        return ResponseResult.success();
    }

    /**
     * 根据用户名查询用户
     * @param username
     * @return
     */
    @GetMapping("getUserVoByUsername")
    public UserVo getUserVoByUsername(@RequestParam("username") String username){
        User user = userDao.findByUsername(username);
        UserVo userVo = new UserVo();
        BeanUtils.copyProperties(user,userVo);
        return userVo;
    }


}
