package com.lg.user.entity;

import lombok.Data;

import javax.persistence.*;
import java.io.Serializable;

/**
 * <p>
 *
 * </p>
 *
 * @author zhanggm
 * @since 2020-06-03
 */
@Data
@Entity
@Table(name = "user")
public class User implements Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * hrID
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    /**
     * 姓名
     */
    private String name;

    private Integer sex;

    /**
     * 手机号码
     */
    private String phone;

    /**
     * 住宅电话
     */
    private String telephone;

    /**
     * 联系地址
     */
    private String address;

    /**
     * 是否可用：1：启用，0：停用
     */
    private Boolean enabled;

    /**
     * 用户名
     */
    private String username;

    /**
     * 密码
     */
    private String password;

    private String remark;

    /**
     * 省
     */
    private Integer province;

    /**
     * 城市
     */
    private Integer city;

    /**
     * 区县
     */
    private Integer district;

    @Transient
    private String token;
}
