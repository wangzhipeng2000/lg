package com.lg.gateway.config;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.Arrays;

/**
 * 跨域配置类
 */
@Configuration
public class CorsConfig {
    @Bean
    public FilterRegistrationBean filterRegistrationBean(){
        //跨域配置
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        final CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowCredentials(true);
        corsConfiguration.setAllowedOrigins(Arrays.asList("*"));
        corsConfiguration.setAllowedMethods(Arrays.asList("*"));
        corsConfiguration.setAllowedHeaders(Arrays.asList("*"));
        corsConfiguration.setMaxAge(3600L);
        source.registerCorsConfiguration("/**",corsConfiguration);
        //配置过滤器
        CorsFilter corsFilter = new CorsFilter(source);
        //注册过滤器
        FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean(corsFilter);
        filterRegistrationBean.setOrder(0);
        return filterRegistrationBean;
    }
}
