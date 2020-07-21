package com.lg.auth.service;

import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.baomidou.mybatisplus.extension.service.IService;
import com.lg.auth.entity.Menu;
import com.lg.auth.entity.MenuVo;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * <p>
 *  服务类
 * </p>
 *
 * @author zhanggm
 * @since 2020-06-03
 */
@Repository
public interface IMenuService extends IService<Menu> {

    List<MenuVo> getMenuVoListByUsername(String username);

    IPage<MenuVo> getPageInfo(MenuVo menuVo, Page page);
}
