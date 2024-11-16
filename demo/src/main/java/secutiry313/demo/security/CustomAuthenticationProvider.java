package secutiry313.demo.security;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import secutiry313.demo.service.UserService;
import java.util.Collection;


public class CustomAuthenticationProvider implements AuthenticationProvider {
    private final UserService userService;
    private final PasswordEncoder bCryptPasswordEncoder;

    public CustomAuthenticationProvider(UserService userService, PasswordEncoder bCryptPasswordEncoder){
        this.userService = userService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Override
    @Transactional
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final String email = authentication.getName();
        final String password = authentication.getCredentials().toString();
        UserDetails user = userService.loadUserByUsername(email);
        String passwordFromBD = user.getPassword();
        if(!bCryptPasswordEncoder.matches(password, passwordFromBD)) {
            throw new BadCredentialsException("Incorrect password");
        }
        return authenticateAgainstThirdPartyAndGetAuthentication(email, password, user.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }

    private static UsernamePasswordAuthenticationToken authenticateAgainstThirdPartyAndGetAuthentication(
            String name, String password, Collection<? extends GrantedAuthority> authorities) {

        final UserDetails principal = new User(name, password, authorities);
        return new UsernamePasswordAuthenticationToken(principal, password, authorities);
    }
}
