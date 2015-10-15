package com.cyriljoui.spring.poc.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import com.cyriljoui.spring.poc.security.token.StatelessTokenAuthenticationFilter;
import com.cyriljoui.spring.poc.security.token.StatelessUsernamePasswordAuthenticationFilter;
import com.cyriljoui.spring.poc.security.token.TokenAuthenticationService;
import com.cyriljoui.spring.poc.security.user.UserDetailsService;

@EnableWebSecurity
@Configuration
@Order(1)
@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableWebMvcSecurity
public class StatelessAuthenticationSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private UserDetailsService userDetailsService;

	@Autowired
	private TokenAuthenticationService tokenAuthenticationService;

	public StatelessAuthenticationSecurityConfig() {
		// Disable defaults
		super(true);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
        http
				.exceptionHandling().and()
				.anonymous().and()
                .servletApi().and()
				.headers().cacheControl().and()
				.authorizeRequests()
								
				//allow anonymous resource requests
                .antMatchers("/").permitAll()
				.antMatchers("/pub/*").permitAll()
				.antMatchers("/favicon.ico").permitAll()
				.antMatchers("/resources/**").permitAll()
				
				//allow anonymous POSTs to login
				.antMatchers(HttpMethod.POST, "/api/login").permitAll()
				
				//allow anonymous GETs to API
				.antMatchers(HttpMethod.GET, "/api/**").permitAll()
				
				//defined Admin only API area
				.antMatchers("/admin/**").hasRole("ADMIN")
				
				//all other request need to be authenticated
				.anyRequest().hasRole("USER").and()				
		
				// custom JSON based authentication by POST of {"username":"<name>","password":"<password>"} which sets the token header upon authentication
				.addFilterBefore(new StatelessUsernamePasswordAuthenticationFilter("/api/login", tokenAuthenticationService, userDetailsService, authenticationManager()), org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class)

				// custom Token based authentication based on the header previously given to the client
				.addFilterBefore(new StatelessTokenAuthenticationFilter(tokenAuthenticationService), org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);
	}
	
	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // Password encrypter for User service and user repository
		auth.userDetailsService(userDetailsService).passwordEncoder(new BCryptPasswordEncoder());
	}

	@Override
	protected UserDetailsService userDetailsService() {
		return userDetailsService;
	}
}
