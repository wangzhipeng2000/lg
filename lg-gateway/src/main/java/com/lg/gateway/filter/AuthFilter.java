package com.lg.gateway.filter;

import com.alibaba.fastjson.JSON;
import com.lg.common.pojo.ResponseResult;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.concurrent.TimeUnit;

/**
 * TODO
 *
 * @author Zgm
 * @version 1.0
 * @date 2020/7/4 0004 8:42
 */
@Component
public class AuthFilter extends ZuulFilter {

    @Autowired
    private RedisTemplate redisTemplate;

    @Override
    public String filterType() {
        return "pre";
    }

    @Override
    public int filterOrder() {
        return 0;
    }

    @Override
    public boolean shouldFilter() {
        //token参数是否存在,如果存在就验证token是否正确
        //不需要登录的接口，不需要过滤：登录接口
        RequestContext requestContext = RequestContext.getCurrentContext();
        HttpServletRequest request = requestContext.getRequest();
        HttpServletResponse response = requestContext.getResponse();
        //获得参数
        String token = request.getHeader("token");
        String requestURI = request.getRequestURI();
        //登录接口不过滤
        if(requestURI.startsWith("/auth/user/login")){
            return false;
        }
        //token是否存在
        System.out.println("token:"+token);
       if(StringUtils.isEmpty(token)){
            try {
                requestContext.setSendZuulResponse(false);
//                requestContext.setResponseStatusCode(403);
                ResponseResult res = ResponseResult.error(10000,"未登录");
                response.setContentType("application/json;chartset=utf-8");
                response.getWriter().write(JSON.toJSONString(res));
            } catch (IOException e) {
                e.printStackTrace();
            }
            return false;
        }
        return true;
    }

    @Override
    public Object run() throws ZuulException {
        RequestContext requestContext = RequestContext.getCurrentContext();
        HttpServletRequest request = requestContext.getRequest();
        HttpServletResponse response = requestContext.getResponse();
        ResponseResult res = ResponseResult.error(10000,"未登录");
        //获得参数
        String token = request.getHeader("token");
        //redis是否有token
        System.out.println(StringUtils.isEmpty(token) || !redisTemplate.hasKey(token));
        if(StringUtils.isEmpty(token) || !redisTemplate.hasKey(token)) {
            try {
                requestContext.setSendZuulResponse(false);
                response.setContentType("application/json;charset=utf-8");
                response.getWriter().write(JSON.toJSONString(res));
            } catch (IOException e) {
                e.printStackTrace();
            }
        }else{
            //重新设置token的过期时间
            redisTemplate.expire(token,60, TimeUnit.SECONDS);
        }
        return null;
    }
}
