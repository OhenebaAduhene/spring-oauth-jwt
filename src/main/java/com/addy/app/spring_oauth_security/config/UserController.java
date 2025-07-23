package com.addy.app.spring_oauth_security.config;

import com.addy.app.spring_oauth_security.model.User;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

import static java.util.stream.Collectors.joining;

@RestController
public class UserController {

    private final JwtEncoder jwtEncoder;

    public UserController(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    @PostMapping("/auth")
    public JWTResponse auth(Authentication authentication) {

        return new JWTResponse(createToken(authentication));
    }



    @GetMapping("/user")
    public User user() {
        return new User("addy", "pass");
    }
    @GetMapping("/admin")
    public User admin () {

        return new User("admin", "pass");
    }

    @PostMapping("/user")
    public User createUser(User user) {
        return user;
    }

    private String createToken(Authentication authentication) {
        var claims = JwtClaimsSet.builder()
                .subject(authentication.getName())
                .claim("scope", createClaims(authentication))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(120))
                .issuer("self")
                .build();

        JwtEncoderParameters params = JwtEncoderParameters.from(claims);
        return jwtEncoder.encode(params).getTokenValue();
    }

    private List<String> createClaims(Authentication authentication) {
       return authentication.getAuthorities()
               .stream()
               .map(GrantedAuthority::getAuthority)
               .collect(Collectors.toList());
    }


}



record JWTResponse(String token) {}