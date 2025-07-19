package com.addy.app.spring_oauth_security.config;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.StringJoiner;
import java.util.stream.Collectors;

import static java.util.stream.Collectors.joining;

@RestController
public class UserController {

    private final JwtEncoder jwtEncoder;

    public UserController(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    @GetMapping("/auth")
    public JWTResponse auth(Authentication authentication) {

        return new JWTResponse(createToken(authentication));
    }



    @GetMapping("/user")
//    @PreAuthorize("hasRole('USER')")
    public Authentication user(Authentication authentication) {

        return authentication;
    }
    @GetMapping("/admin")
//    @PreAuthorize("hasRole('ADMIN')")
    public Authentication admin(Authentication authentication) {

        return authentication;
    }

    private String createToken(Authentication authentication) {
        var claims = JwtClaimsSet.builder()
                .subject(authentication.getName())
                .claim("scope", createClaims(authentication))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .issuer("self")
                .build();

        JwtEncoderParameters params = JwtEncoderParameters.from(claims);
        return jwtEncoder.encode(params).getTokenValue();
    }

    private String createClaims(Authentication authentication) {
       return authentication.getAuthorities().toString();
    }


}



record JWTResponse(String token) {}