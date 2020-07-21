package com.lg.other;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;


@EnableEurekaClient
@SpringBootApplication
public class OtherApp {
    public static void main(String[] args) {
        SpringApplication.run(OtherApp.class,args);
    }
}
