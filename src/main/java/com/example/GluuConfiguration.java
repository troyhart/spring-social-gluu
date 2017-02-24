package com.example;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.resource.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

import java.util.Arrays;

/**
 * Created by eugeniuparvan on 2/23/17.
 */
@Configuration
public class GluuConfiguration extends ResourceServerTokenServicesConfiguration {

    @Value("${security.oauth2.resource.userInfoUri}")
    private String userInfoUri;

    @Value("${security.oauth2.client.clientId}")
    private String clientId;

    @Bean
    @Primary
    public ResourceServerTokenServices userInfoTokenServices() {
        return new GluuUserInfoTokenService(userInfoUri, clientId);
    }

    @Configuration
    protected static class RemoteTokenServicesConfiguration {
        @Configuration
        protected static class UserInfoTokenServicesConfiguration {
            private final ResourceServerProperties sso;
            private final OAuth2RestOperations restTemplate;
            private final AuthoritiesExtractor authoritiesExtractor;
            private final PrincipalExtractor principalExtractor;

            public UserInfoTokenServicesConfiguration(ResourceServerProperties sso, UserInfoRestTemplateFactory restTemplateFactory, ObjectProvider<AuthoritiesExtractor> authoritiesExtractor, ObjectProvider<PrincipalExtractor> principalExtractor) {
                this.sso = sso;
                this.restTemplate = restTemplateFactory.getUserInfoRestTemplate();
                this.authoritiesExtractor = (AuthoritiesExtractor) authoritiesExtractor.getIfAvailable();
                this.principalExtractor = (PrincipalExtractor) principalExtractor.getIfAvailable();

                AccessTokenProvider accessTokenProvider = new AccessTokenProviderChain(Arrays.<AccessTokenProvider>asList(
                        new GluuAuthorizationCodeAccessTokenProvider(), new ImplicitAccessTokenProvider(),
                        new ResourceOwnerPasswordAccessTokenProvider()));
                ((OAuth2RestTemplate) this.restTemplate).setAccessTokenProvider(accessTokenProvider);
            }

            @Bean
            public UserInfoTokenServices userInfoTokenServices() {
                UserInfoTokenServices services = new UserInfoTokenServices(this.sso.getUserInfoUri(), this.sso.getClientId());

                services.setRestTemplate(this.restTemplate);
                services.setTokenType(this.sso.getTokenType());
                if (this.authoritiesExtractor != null) {
                    services.setAuthoritiesExtractor(this.authoritiesExtractor);
                }

                if (this.principalExtractor != null) {
                    services.setPrincipalExtractor(this.principalExtractor);
                }

                return services;
            }
        }

    }
}
