package com.lg.auth.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.Accessors;

import java.io.Serializable;
import java.time.LocalDateTime;

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
public class Menu implements Serializable {

    private static final long serialVersionUID = 1L;

    @TableId(value = "id", type = IdType.AUTO)
    private Integer id;

    private String url;

    /**
     * vue组件的访问路径
     */
    private String path;

    /**
     * vue组件名称
     */
    private String component;

    /**
     * 名称
     */
    private String name;

    /**
     * 菜单图标名称
     */
    @TableField("iconCls")
    private String iconCls;

    @TableField("keepAlive")
    private Boolean keepAlive;

    /**
     * 是否需要认证
     */
    @TableField("requireAuth")
    private Boolean requireAuth;

    /**
     * 父Id
     */
    @TableField("parentId")
    private Integer parentId;

    /**
     * 是否可用
     */
    private Boolean enabled;

    /**
     * 创建时间
     */
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm")
    private LocalDateTime createTime;


}
