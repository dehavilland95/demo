package secutiry313.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import secutiry313.demo.security.CustomAuthenticationProvider;
import secutiry313.demo.utils.CustomLoginSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomAuthenticationProvider authProvider;

    public SecurityConfig(CustomAuthenticationProvider authProvider) {
        this.authProvider = authProvider;
    }

    @Bean
    public AuthenticationSuccessHandler myAuthenticationSuccessHandler(){
        return new CustomLoginSuccessHandler();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
       http
           .authorizeHttpRequests((requests) -> requests
                   .requestMatchers("/registration").not().authenticated()
                   .requestMatchers("/admin").hasRole("ADMIN")
                   .requestMatchers("/user").hasAnyRole("USER", "ADMIN")
           .requestMatchers("/", "/login", "/error").permitAll()
           .anyRequest().authenticated())
               .formLogin(formLogin -> formLogin.loginPage("/login")
                       .loginProcessingUrl("/login")
                       .successHandler(myAuthenticationSuccessHandler())
                       .permitAll())
               .logout(logout ->
                       logout.logoutUrl("/logout")
                       .logoutSuccessUrl("/login"));
        return http.build();
    }

    @Bean
    public AuthenticationManager authManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder =
                http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.authenticationProvider(authProvider);
        return authenticationManagerBuilder.build();
    }
}