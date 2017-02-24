package com.example;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerTokenServicesConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

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
}
