package kh.edu.cstad.identity.config;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import kh.edu.cstad.identity.repository.JpaRegisteredClientRepository;
import kh.edu.cstad.identity.repository.UserRepository;
import kh.edu.cstad.identity.service.CustomUserDetailService;
import kh.edu.cstad.identity.service.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.core.Authentication;

import java.time.Duration;
import java.util.HashSet;
import java.util.Set;

@Configuration()
@RequiredArgsConstructor
@EnableWebSecurity
public class AuthorizationServerConfig {

    private final UserRepository userRepository;

    private final JpaRegisteredClientRepository jpaRegisteredClientRepository;


    private final PasswordEncoder passwordEncoder;


    @Bean
    @Order(1)
    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());

          http.csrf(AbstractHttpConfigurer::disable);

        http.exceptionHandling(exceptionHandling -> {
            exceptionHandling.defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint("/login"),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
            );
        });

        http.oauth2ResourceServer(server -> {
            server.jwt(Customizer.withDefaults());
        });

        http.cors(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    @Primary
    public RegisteredClientRepository registeredClientRepository() {

        TokenSettings tokenSettings = TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                .accessTokenTimeToLive(Duration.ofDays(1))
                .reuseRefreshTokens(false)
                .refreshTokenTimeToLive(Duration.ofDays(3))
                .build();

        ClientSettings clientSettings = ClientSettings.builder()
                .requireProofKey(true)
                .requireAuthorizationConsent(true)
                .build();

        // Next.js Client
        var nextjs = RegisteredClient.withId("nextjs")
                .clientId("nextjs")
                .clientSecret(passwordEncoder.encode("nextjs123"))
                .scopes(scopes -> {
                    scopes.add(OidcScopes.OPENID);
                    scopes.add(OidcScopes.PROFILE);
                })
                .redirectUris(uri -> {
                    uri.add("http://localhost:8085/login/oauth2/code/nextjs");
                })
                .postLogoutRedirectUris(uri -> {
                    uri.add("http://localhost:8085");
                })
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantTypes(grantTypes -> {
                    grantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE);
                    grantTypes.add(AuthorizationGrantType.REFRESH_TOKEN);
                })
                .clientSettings(clientSettings)
                .tokenSettings(tokenSettings)
                .build();

        // GitHub Client
        var github = RegisteredClient.withId("github")
                .clientId("Ov23liZp7jXgv2WZShWi")  // Replace with your GitHub Client ID
                .clientSecret(passwordEncoder.encode("2c0592220b43a3442cd89478dd75ffa3357936f2"))  // Replace with your GitHub Client Secret
                .scopes(scopes -> {
                    scopes.add("user:email");  // Add any required scopes here
                })
                .redirectUris(uri -> {
                    uri.add("http://localhost:8085/login/oauth2/code/github");
                })
                .postLogoutRedirectUris(uri -> {
                    uri.add("http://localhost:8085");
                })
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantTypes(grantTypes -> {
                    grantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE);
                    grantTypes.add(AuthorizationGrantType.REFRESH_TOKEN);
                })
                .clientSettings(clientSettings)
                .tokenSettings(tokenSettings)
                .build();

        // Telegram Client
        var telegram = RegisteredClient.withId("telegram")
                .clientId("telegram")
                .clientSecret(passwordEncoder.encode("telegram-secret"))
                .scopes(scopes -> {
                    scopes.add("openid");
                    scopes.add("profile");
                })
                .redirectUris(uri -> {
                    uri.add("http://localhost:8085/login/oauth2/code/telegram");
                })
                .postLogoutRedirectUris(uri -> {
                    uri.add("http://localhost:8085");
                })
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantTypes(grantTypes -> {
                    grantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE);
                    grantTypes.add(AuthorizationGrantType.REFRESH_TOKEN);
                })
                .clientSettings(clientSettings)
                .tokenSettings(tokenSettings)
                .build();

        // Google Client
        var google = RegisteredClient.withId("google")
                .clientId("1269394266-sqbgeggcmk05hop03kkggb3jfi6tb5lf.apps.googleusercontent.com")  // Replace with your Google Client ID
                .clientSecret(passwordEncoder.encode("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"))  // Replace with your Google Client Secret
                .scopes(scopes -> {
                    scopes.add(OidcScopes.OPENID);  // OpenID scope for authentication
                    scopes.add(OidcScopes.PROFILE);  // Profile scope to access user profile information
                    scopes.add("email");  // Email scope to access user's email
                })
                .redirectUris(uri -> {
                    uri.add("http://localhost:8085/login/oauth2/code/google");  // Google OAuth2 redirect URI
                })
                .postLogoutRedirectUris(uri -> {
                    uri.add("http://localhost:8085");
                })
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantTypes(grantTypes -> {
                    grantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE);
                    grantTypes.add(AuthorizationGrantType.REFRESH_TOKEN);
                })
                .clientSettings(clientSettings)
                .tokenSettings(tokenSettings)
                .build();

        // Persist Registered Clients to Repository
        RegisteredClient registeredClient = jpaRegisteredClientRepository.findByClientId("nextjs");
        if (registeredClient == null) {
            jpaRegisteredClientRepository.save(nextjs);
        }

        registeredClient = jpaRegisteredClientRepository.findByClientId("github");
        if (registeredClient == null) {
            jpaRegisteredClientRepository.save(github);
        }

        registeredClient = jpaRegisteredClientRepository.findByClientId("telegram");
        if (registeredClient == null) {
            jpaRegisteredClientRepository.save(telegram);
        }

        registeredClient = jpaRegisteredClientRepository.findByClientId("google");
        if (registeredClient == null) {
            jpaRegisteredClientRepository.save(google);
        }

        return jpaRegisteredClientRepository;
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorizeRequests ->
                        authorizeRequests
                                .requestMatchers("/public/**").permitAll() // Public endpoints
                                .anyRequest().authenticated() // All other endpoints require authentication
                )
                .oauth2Login(Customizer.withDefaults())
                .formLogin(Customizer.withDefaults());


        http.cors(Customizer.withDefaults());

        return http.build();
    }


    @Bean
    public AuthorizationServerSettings providerSetting() {

        return AuthorizationServerSettings
                .builder()
                .issuer("http://localhost:8080")
                .build();
    }


    @Bean
    public UserDetailsService userDetailsService() {
        return new CustomUserDetailService(userRepository);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {

            Authentication authentication = context.getPrincipal();
            CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();

            if (context.getTokenType().getValue().equals("id_token")) {
                context.getClaims().claim("soknem", "pov-soknem2");
            }

            if (context.getTokenType().getValue().equals("access_token")) {
                Set<String> scopes = new HashSet<>(context.getAuthorizedScopes());
                authentication
                        .getAuthorities()
                        .forEach(grantedAuthority -> scopes.add(grantedAuthority.getAuthority()));
                context.getClaims()
                        .id(authentication.getName())
                        .subject(authentication.getName())
                        .claim("scope", scopes);
//                        .claim("id", customUserDetails.getUser().getId()==null?"1":customUserDetails.getUser().getId());
//                        .claim("email", customUserDetails.getUser().getEmail()==null?"email":
//                                customUserDetails.getUser().getEmail()); // Add email claim
//                        .claim("name", customUserDetails.getUser().getName()==null?"name":customUserDetails.getUser().getName());

            }
        };
    }
//
//    @Bean
//    CorsConfigurationSource corsConfigurationSource() {
//        CorsConfiguration configuration = new CorsConfiguration();
//        configuration.setAllowedOrigins(List.of("*")); //allows React to access the API from origin on port 3000. Change accordingly
//        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
//        configuration.addAllowedHeader("*");
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        source.registerCorsConfiguration("/**", configuration);
//        return source;
//    }



}
