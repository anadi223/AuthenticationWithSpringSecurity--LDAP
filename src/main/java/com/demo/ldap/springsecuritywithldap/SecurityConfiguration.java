package com.demo.ldap.springsecuritywithldap;


import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected  void configure(HttpSecurity http) throws Exception{
        http.authorizeRequests().anyRequest().fullyAuthenticated().and().formLogin(); // I want to have every request to be authorized with full authentication
    }

    //LDAP Authentication
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
        //For LDAP Based Authentication --telling spring security how the ldif structure is stored
        auth.ldapAuthentication().
                userDnPatterns("uid={0},ou=people")//format jo ldif wali file me hai {0} user info jayegi yhn
                .groupSearchBase("ou=groups") //organisation unit
                .contextSource()
                .url("ldap://localhost:8389/dc=springframework,dc=org")//jahan ldap server hosted hai
                .and()
                .passwordCompare()
                .passwordEncoder(new LdapShaPasswordEncoder())
                .passwordAttribute("userPassword"); //password attribute jo hai


    }

}
