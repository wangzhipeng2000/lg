package com.lg.auth.feign;


import com.lg.user.api.UserApi;
import org.springframework.cloud.openfeign.FeignClient;

@FeignClient(name = "lg-user")
public interface UserClient extends UserApi {

}
