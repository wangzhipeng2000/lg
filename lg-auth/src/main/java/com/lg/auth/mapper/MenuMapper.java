package com.lg.auth.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.lg.auth.entity.Menu;
import com.lg.auth.entity.MenuVo;
import org.apache.ibatis.annotations.Param;

/**
 * <p>
 *  Mapper 接口
 * </p>
 *
 * @author zhanggm
 * @since 2020-06-03
 */
public interface MenuMapper extends BaseMapper<Menu> {

    IPage<MenuVo> selectPageInfo(@Param("menuVo") MenuVo menuVo, Page page);
}
