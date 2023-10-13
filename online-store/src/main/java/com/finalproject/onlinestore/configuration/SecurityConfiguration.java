package com.finalproject.onlinestore.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;


@Configuration
@EnableMethodSecurity
@EnableWebSecurity
public class SecurityConfiguration {
    private UserDetailsService userDetailsService;

    public SecurityConfiguration(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    // Authorization
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeHttpRequests((authorize) ->
                           authorize
//                                     // Configure request matchers for authorization

//                                requestMatchers(HttpMethod.GET,"/api/myController/welcome").permitAll()
//                                .requestMatchers(HttpMethod.GET,"api/myController/number").hasRole("ADMIN")
//
//                                        // allows all GET methods to be accessed by everyone no authentication required.
                                          .requestMatchers("/api/auth/**").permitAll()
//                                        .requestMatchers("/swagger-ui/**").permitAll()
//                                        .requestMatchers("/v3/api-docs/**").permitAll()
//                                        .requestMatchers(HttpMethod.GET,"/api/**").permitAll()
//                                        .requestMatchers(HttpMethod.GET,"/api/student/findAll").hasAnyRole("ADMIN","USER")
//                                        .requestMatchers(HttpMethod.GET,"/api/user").hasRole("ADMIN")
//                                        .requestMatchers(HttpMethod.DELETE,"/api/user/deleteById/{id}").hasRole("ADMIN")
//                                        .requestMatchers(HttpMethod.GET, "/api/user/findById/{id}").hasRole("ADMIN")
//                                        .requestMatchers(HttpMethod.GET, "/api/student/{password}").permitAll()
//                                        .requestMatchers(HttpMethod.GET, "/api/student/save").hasRole("ADMIN")
//                                        .requestMatchers(HttpMethod.POST,"/api/user/save").hasAnyRole("ADMIN","USER")
//                                        .requestMatchers(HttpMethod.PUT,"/api/user/{id}").hasRole("USER")
//                                        .requestMatchers(HttpMethod.POST,"/api/students/{studentsId}/comments").hasAnyRole("ADMIN","USER")
//                                        .requestMatchers(HttpMethod.GET,"/api/students/{studentId}/comments").permitAll()
//                                        .requestMatchers(HttpMethod.GET,"/api/students/{studentId}/comments/{commentId}").permitAll()
//                                        .requestMatchers(HttpMethod.PUT,"/api/students/{studentId}/comments/{commentId}").hasRole("ADMIN")
//                                        .requestMatchers(HttpMethod.DELETE, "api/student/deleteById/{id}").hasRole("ADMIN")
//                                        .requestMatchers(HttpMethod.DELETE, "api/students/{studentId}/comments/{commentId}").hasRole("ADMIN")
                                          .requestMatchers(HttpMethod.POST, "api/categories").hasRole("ADMIN")
                                          .requestMatchers(HttpMethod.POST, "api/products").hasRole("ADMIN")
                                          .requestMatchers(HttpMethod.GET,"/api/products/findAll").permitAll()
                                           .requestMatchers(HttpMethod.POST, "api/product/{productId}/reviews").hasRole("ADMIN")
//                                        .requestMatchers(HttpMethod.PUT, "api/categories/update/{categoryId}").hasRole("ADMIN")
//                                        .requestMatchers(HttpMethod.DELETE,"/api/categories/deleteById/{categoryId}").hasRole("ADMIN")
//                                        .requestMatchers(HttpMethod.GET,"/api/student/findByCategoryId/{categoryId}").hasAnyRole("ADMIN","USER")
                                        .anyRequest().authenticated()
                )
                .httpBasic(Customizer.withDefaults());


        return http.build();

    }

    // PasswordEncoder bean configuration
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
//        return NoOpPasswordEncoder.getInstance();
    }


    //     DAO Authentication Manager
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }



// InMemory Authentication
//    @Bean
//    public UserDetailsService userDetailsService() {
//        UserDetails user = User.builder()
//                .username("user")
//                .password(passwordEncoder().encode("password"))
//                .roles("USER")
//                .build();
//
//        UserDetails admin = User.builder()
//                .username("admin")
//                .password("admin")
//                .roles("ADMIN")
//                .build();
//        return new InMemoryUserDetailsManager(user,admin);
//    }


}

