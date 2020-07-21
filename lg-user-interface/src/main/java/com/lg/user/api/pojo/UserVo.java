package com.lg.user.api.pojo;

import lombok.Data;

import java.io.Serializable;
import java.util.List;

/**
 * @author Zgm
 * @version 1.0
 * @date 2020/7/4 0004 9:58
 */
@Data
public class UserVo implements Serializable {
    private Integer id;
    private String username;
    private String password;
    private Boolean enabled;
    private String token;
    private List<Integer> roleIdList;
}
