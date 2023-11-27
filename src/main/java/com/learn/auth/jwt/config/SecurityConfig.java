package com.learn.auth.jwt.config;

import com.learn.auth.jwt.security.JwtAuthenticationEntryPoint;
import com.learn.auth.jwt.security.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    @Autowired
    private JwtAuthenticationEntryPoint point;

    @Autowired
    private JwtAuthenticationFilter filter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.csrf(csrf -> csrf.disable())
                .cors(cors -> cors.disable())
                .authorizeHttpRequests(
                        auth ->
                                auth.requestMatchers("/api/**").authenticated()
                                        .requestMatchers("/auth/token").permitAll()
                                        .anyRequest().authenticated())
                .exceptionHandling(ex -> ex.authenticationEntryPoint(point))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        /*
            This line ensures that your custom JwtAuthenticationFilter is executed before the standard UsernamePasswordAuthenticationFilter.
            The UsernamePasswordAuthenticationFilter is a standard Spring Security filter responsible for processing form-based authentication.
         */
        http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);

        /*
            Used to finalize the configuration of the HttpSecurity object
            Returns an instance of SecurityFilterChain, which is a chain of filters that will be applied to incoming HTTP requests.
         */
        return http.build();

    }

}


/*
    When you use permitAll() you are not disabling the filters, you are just specifying that you do not want to apply any authorization checks for that RequestMatcher. All the filters will still work.
    The JwtAuthenticationFilter will be invoked but since you configure permitAll() for that endpoint, it will always grant access.
 */