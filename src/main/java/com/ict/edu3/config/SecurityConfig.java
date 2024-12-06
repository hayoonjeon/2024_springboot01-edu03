package com.ict.edu3.config;

import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.ict.edu3.common.util.JwtUtil;
import com.ict.edu3.domain.auth.service.MyUserDetailService;
import com.ict.edu3.jwt.JwtRequestFilter;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Configuration
public class SecurityConfig {

    private final JwtRequestFilter jwtRequestFilter;
    private final JwtUtil jwtUtil;
    private final MyUserDetailService userDetailService;


    public SecurityConfig(JwtRequestFilter jwtRequestFilter,JwtUtil jwtUtil,MyUserDetailService userDetailService) {
        log.info("SecurityConfig 호출\n");
        this.jwtRequestFilter = jwtRequestFilter;
        this.jwtUtil = jwtUtil;
        this.userDetailService=userDetailService;
    }

    // 서버에 들어는 모든 요청은 SecurityFilterChain 을 거친다.
    // addFilterBefore 때문에 JwtRequestFilter가 먼저 실행된다.
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        log.info("SecurityFilterChain 호출\n");
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf.disable())
                // 요청별 권한 설정
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/upload/**").permitAll()
                        .requestMatchers("/oauth2/**").permitAll()
                        // 특정 URL에 인증없이 허용
                        .requestMatchers("/api/members/join", "/api/members/login",
                                "/api/guestbook/list", "/api/guestbook/detail/**", "api/guestbook/download/**")
                        .permitAll()
                        // 나머지는 인증 필요
                        .anyRequest().authenticated())
                // oauth2login 설정
                // successHandler : 로그인성공시 호출
                // userInfoEndpoint : 인증과정에서 인증된 사용자에 대한 정보제공API 엔드포인트
                // .oauth2Login(oauth2 -> oauth2
                        // .successHandler(oauth2AuthenticationSuccesHandler)
                        // .userInfoEndpoint(userInfo -> userInfo.userService(oAuth2UserService())))
                .addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // @Bean
    // Oauth2AuthenticationSuccesHandler oauth2AuthenticationSuccesHandler(){
    //     return new Oauth2AuthenticationSuccesHandler(jwtUtil,userDetailService);
    // }

    // @Bean
    // OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService() {
    //     return new CustomerOAuth2UserService();
    // }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfig = new CorsConfiguration();

        // 허용할 Origin 설정
        corsConfig.setAllowedOrigins(Arrays.asList("http://localhost:3000"));
        // 허용할 http 메서드 설정
        corsConfig.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        // 허용할 헤더 설정
        corsConfig.setAllowedHeaders(Arrays.asList("*"));
        // 인증정보 허용
        corsConfig.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig);
        return source;
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }
}