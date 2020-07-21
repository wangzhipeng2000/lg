package com.lg.auth.entity;

import lombok.Data;

import java.util.List;

@Data
public class RoleVo {
    private Integer roleId;
    private List<Integer> menuIdList;
}
