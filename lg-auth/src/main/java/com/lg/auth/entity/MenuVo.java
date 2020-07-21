package com.lg.auth.entity;

import lombok.Data;

import java.util.List;

@Data
public class MenuVo extends Menu {

    private List<MenuVo> subMenus;

    private String parentName;
}
