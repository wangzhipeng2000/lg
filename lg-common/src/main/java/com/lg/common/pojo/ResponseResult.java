package com.lg.common.pojo;

import lombok.Data;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
public class ResponseResult {
    //成功返回真，失败返回假（非逻辑内时候，返回false）
    private boolean result;
    //编码
    private int code;
    //说明
    private String msg;
    //接口数据
    private Object data;

    public static ResponseResult success(Object data){
        return new ResponseResult().setResult(true).setData(data);
    }

    public static ResponseResult success(){
        return new ResponseResult().setResult(true);
    }

    public static ResponseResult error(int code,String msg){
        return new ResponseResult().setMsg(msg).setCode(code);
    }

    public static ResponseResult error(String msg){
        return new ResponseResult().setMsg(msg);
    }


}
