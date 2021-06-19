package com.teng.security.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * @author shkstart
 * @create 2021-06-17 22:17
 */
@EnableWebSecurity
public class MySecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //super.configure(http);
        http.authorizeRequests().mvcMatchers("/").permitAll()
                .mvcMatchers("/level1/**").hasRole("vip1")
                .mvcMatchers("/level2/**").hasRole("vip2")
                .mvcMatchers("/level3/**").hasRole("vip3");

        //开启登录
        http.formLogin().usernameParameter("user").passwordParameter("psw")
                .loginPage("/userlogin");

        //开启注销功能
        http.logout().logoutSuccessUrl("/");

        //开启记住我
        http.rememberMe().rememberMeParameter("remember");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //super.configure(auth);
        auth.inMemoryAuthentication()
                .withUser("zhangs").password("123").roles("vip1","vip2")
                .and()
                .withUser("lisi").password("123").roles("vip2","vip3")
                .and()
                .withUser("wangwu").password("123").roles("vip1","vip3");
    }
}
