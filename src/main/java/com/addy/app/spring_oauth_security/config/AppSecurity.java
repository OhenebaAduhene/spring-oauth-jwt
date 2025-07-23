package com.addy.app.spring_oauth_security.config;

import com.addy.app.spring_oauth_security.exception.TokenValidationError;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.UUID;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION;

@Configuration
public class AppSecurity {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests( auth ->
                auth
                        .requestMatchers("/admin").hasAnyAuthority("SCOPE_ROLE_ADMIN")
                        .requestMatchers("/user").hasAuthority("SCOPE_ROLE_USER")
                        .anyRequest()
                        .authenticated()
        );
//        http.formLogin(Customizer.withDefaults());

        http.csrf(AbstractHttpConfigurer::disable);
        http.sessionManagement(
                session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );
        http.headers( header ->
                header.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable) );
        http.httpBasic(withDefaults());
        http.oauth2ResourceServer(oauth2 ->
                oauth2.jwt(withDefaults())
                        .authenticationEntryPoint(new TokenValidationError())
        );
        return http.build();
    }

    @Bean
    public DataSource dataSource() {
        return new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .addScript(DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();
    }

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        UserDetails addy = User
                .withUsername("addy")
                .passwordEncoder(bcrypt -> passwordEncoder().encode(bcrypt))
                .password("addy")
                .roles("USER").build();
        UserDetails kofi = User
                .withUsername("kofi")
                .passwordEncoder(bcrypt -> passwordEncoder().encode(bcrypt))
                .password("pass")
                .roles("USER","ADMIN").build();
        var userDetailsManager = new JdbcUserDetailsManager(dataSource);
        userDetailsManager.createUser(addy);
        userDetailsManager.createUser(kofi);
        return userDetailsManager;
    }


    //gen keypair
    @Bean
    public KeyPair keyPair () {
        try {
            return KeyPairGenerator.getInstance("RSA").generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

//RSA to public
    @Bean
    RSAKey rsaKey(KeyPair keyPair) {
       return new RSAKey.Builder((RSAPublicKey)keyPair.getPublic())
                .privateKey(keyPair.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    //Define JWKSource
    @Bean
    public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
        JWKSet jwkSet = new JWKSet(rsaKey);

        return (jwkSelector, context) -> jwkSelector.select(jwkSet);

//        return new JWKSource<SecurityContext>() {
//            @Override
//            public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) throws KeySourceException {
//                return jwkSelector.select(jwkSet);
//            }
//        };
    }
    //encode key
    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

//decode key
    @Bean
    public JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {
        var jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build();
        jwtDecoder.setJwtValidator(tokenValidator());
        return jwtDecoder;
    }

    private OAuth2TokenValidator<Jwt> tokenValidator() {
        return jwt -> {
            try {
                // validate expiration date
                if (jwt.getExpiresAt() == null || jwt.getExpiresAt().isBefore(Instant.now())) {
                    return OAuth2TokenValidatorResult.failure(
                            new OAuth2Error("invalid_token", "Token is expired", null));
                }

                return OAuth2TokenValidatorResult.success();

            } catch (Exception e) {
                return OAuth2TokenValidatorResult.failure(
                        new OAuth2Error("invalid_token", "JWT validation error: " + e.getMessage(), null));
            }
        };
    }
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

//    @Bean
//    public Supplier<JwtDecoder> jwtDecoderSupplier(RSAKey rsaKey) {
//        return () -> {
//            try {
//                return NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build();
//            } catch (JOSEException e) {
//                throw new RuntimeException(e);
//            }
//        };
//    }
//
//    @Bean
//    public String supplierJwtDecoder(Supplier<JwtDecoder> jwtDecoderSupplier) {
//        var supplierJwtDecoder = new SupplierJwtDecoder(jwtDecoderSupplier);
//        return supplierJwtDecoder.decode("token").getTokenValue();
//    }

}


