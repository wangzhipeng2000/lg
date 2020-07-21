package com.lg.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.cloud.openfeign.EnableFeignClients;

/**
 * 启动类
 */
@EnableFeignClients
@EnableEurekaClient
@SpringBootApplication
public class AuthApp {
    public static void main(String[] args) {
        SpringApplication.run(AuthApp.class,args);
    }
}
