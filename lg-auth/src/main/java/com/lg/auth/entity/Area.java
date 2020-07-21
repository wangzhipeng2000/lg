package com.lg.auth.entity;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.Accessors;

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
@EqualsAndHashCode(callSuper = false)
@Accessors(chain = true)
public class Area implements Serializable {

    private static final long serialVersionUID = 1L;

    private Integer id;

    private String code;

    private String name;

    private Integer pid;

    private Integer lft;

    private Integer rgt;

    private String nameEn;

    private String shortNameEn;

    private Boolean isShow;


}
