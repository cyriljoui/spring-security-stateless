package com.cyriljoui.spring.poc.security;

import com.cyriljoui.spring.poc.security.user.UserRepository;
import com.cyriljoui.spring.poc.security.user.UserRole;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.filter.CharacterEncodingFilter;
import com.cyriljoui.spring.poc.security.user.User;

import javax.servlet.Filter;

@SpringBootApplication
@ComponentScan
public class Application {

    public static void main(String[] args) throws Throwable {
        SpringApplication.run(Application.class, args);
    }

    /**
     * Default user creation for test purposes.
     * @return
     */
    @Bean
    public InitializingBean insertDefaultUsers() {
        return new InitializingBean() {
            @Autowired
            private UserRepository userRepository;

            @Override
            public void afterPropertiesSet() {
                addUser("admin", "admin");
                addUser("user", "user");
                addAnnotUser("annot", "annot");
            }

            private void addUser(String username, String password) {
                User user = new User();
                user.setUsername(username);
                user.setPassword(new BCryptPasswordEncoder().encode(password));
                user.grantRole(username.equals("admin") ? UserRole.ADMIN : UserRole.USER);
                userRepository.save(user);
            }
            private void addAnnotUser(String username, String password) {
                User user = new User();
                user.setUsername(username);
                user.setPassword(new BCryptPasswordEncoder().encode(password));
                user.grantRole(UserRole.ANNOT);
                user.grantRole(UserRole.USER);
                userRepository.save(user);
            }
        };
    }

    @Bean
    public Filter characterEncodingFilter() {
        CharacterEncodingFilter characterEncodingFilter = new CharacterEncodingFilter();
        characterEncodingFilter.setEncoding("UTF-8");
        characterEncodingFilter.setForceEncoding(true);
        return characterEncodingFilter;
    }
}
