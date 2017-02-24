package com.example;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.client.filter.state.DefaultStateKeyGenerator;
import org.springframework.security.oauth2.client.filter.state.StateKeyGenerator;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.UserApprovalRequiredException;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.token.*;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.ResponseExtractor;

import java.io.IOException;
import java.net.URI;
import java.util.*;

/**
 * Created by eugeniuparvan on 2/23/17.
 */
public class GluuAuthorizationCodeAccessTokenProvider extends OAuth2AccessTokenSupport implements AccessTokenProvider {
    private StateKeyGenerator stateKeyGenerator = new DefaultStateKeyGenerator();
    private String scopePrefix = "scope.";
    private RequestEnhancer authorizationRequestEnhancer = new DefaultRequestEnhancer();
    private boolean stateMandatory = true;

    public GluuAuthorizationCodeAccessTokenProvider() {
    }

    public void setStateMandatory(boolean stateMandatory) {
        this.stateMandatory = stateMandatory;
    }

    public void setAuthorizationRequestEnhancer(RequestEnhancer authorizationRequestEnhancer) {
        this.authorizationRequestEnhancer = authorizationRequestEnhancer;
    }

    public void setScopePrefix(String scopePrefix) {
        this.scopePrefix = scopePrefix;
    }

    public void setStateKeyGenerator(StateKeyGenerator stateKeyGenerator) {
        this.stateKeyGenerator = stateKeyGenerator;
    }

    public boolean supportsResource(OAuth2ProtectedResourceDetails resource) {
        return resource instanceof AuthorizationCodeResourceDetails && "authorization_code".equals(resource.getGrantType());
    }

    public boolean supportsRefresh(OAuth2ProtectedResourceDetails resource) {
        return this.supportsResource(resource);
    }

    public String obtainAuthorizationCode(OAuth2ProtectedResourceDetails details, final AccessTokenRequest request) throws UserRedirectRequiredException, UserApprovalRequiredException, AccessDeniedException, OAuth2AccessDeniedException {
        AuthorizationCodeResourceDetails resource = (AuthorizationCodeResourceDetails)details;
        HttpHeaders headers = this.getHeadersForAuthorizationRequest(request);
        LinkedMultiValueMap form = new LinkedMultiValueMap();
        if(request.containsKey("user_oauth_approval")) {
            form.set("user_oauth_approval", request.getFirst("user_oauth_approval"));
            Iterator copy = details.getScope().iterator();

            while(copy.hasNext()) {
                String delegate = (String)copy.next();
                form.set(this.scopePrefix + delegate, request.getFirst("user_oauth_approval"));
            }
        } else {
            form.putAll(this.getParametersForAuthorizeRequest(resource, request));
        }

        this.authorizationRequestEnhancer.enhance(request, resource, form, headers);
        final ResponseExtractor delegate1 = this.getAuthorizationResponseExtractor();
        ResponseExtractor extractor = new ResponseExtractor() {
            public ResponseEntity<Void> extractData(ClientHttpResponse response) throws IOException {
                if(response.getHeaders().containsKey("Set-Cookie")) {
                    request.setCookie(response.getHeaders().getFirst("Set-Cookie"));
                }

                return (ResponseEntity)delegate1.extractData(response);
            }
        };
        ResponseEntity response = (ResponseEntity)this.getRestTemplate().execute(resource.getUserAuthorizationUri(), HttpMethod.POST, this.getRequestCallback(resource, form, headers), extractor, form.toSingleValueMap());
        if(response.getStatusCode() == HttpStatus.OK) {
            throw this.getUserApprovalSignal(resource, request);
        } else {
            URI location = response.getHeaders().getLocation();
            String query = location.getQuery();
            Map map = OAuth2Utils.extractMap(query);
            String code;
            if(map.containsKey("state")) {
                request.setStateKey((String)map.get("state"));
                if(request.getPreservedState() == null) {
                    code = resource.getRedirectUri(request);
                    if(code != null) {
                        request.setPreservedState(code);
                    } else {
                        request.setPreservedState(new Object());
                    }
                }
            }

            code = (String)map.get("code");
            if(code == null) {
                throw new UserRedirectRequiredException(location.toString(), form.toSingleValueMap());
            } else {
                request.set("code", code);
                return code;
            }
        }
    }

    protected ResponseExtractor<ResponseEntity<Void>> getAuthorizationResponseExtractor() {
        return new ResponseExtractor() {
            public ResponseEntity<Void> extractData(ClientHttpResponse response) throws IOException {
                return new ResponseEntity(response.getHeaders(), response.getStatusCode());
            }
        };
    }

    public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails details, AccessTokenRequest request) throws UserRedirectRequiredException, UserApprovalRequiredException, AccessDeniedException, OAuth2AccessDeniedException {
        AuthorizationCodeResourceDetails resource = (AuthorizationCodeResourceDetails)details;
        if(request.getAuthorizationCode() == null) {
            if(request.getStateKey() == null) {
                throw this.getRedirectForAuthorization(resource, request);
            }

            this.obtainAuthorizationCode(resource, request);
        }

        return this.retrieveToken(request, resource, this.getParametersForTokenRequest(resource, request), this.getHeadersForTokenRequest(request));
    }

    public OAuth2AccessToken refreshAccessToken(OAuth2ProtectedResourceDetails resource, OAuth2RefreshToken refreshToken, AccessTokenRequest request) throws UserRedirectRequiredException, OAuth2AccessDeniedException {
        LinkedMultiValueMap form = new LinkedMultiValueMap();
        form.add("grant_type", "refresh_token");
        form.add("refresh_token", refreshToken.getValue());

        try {
            return this.retrieveToken(request, resource, form, this.getHeadersForTokenRequest(request));
        } catch (OAuth2AccessDeniedException var6) {
            throw this.getRedirectForAuthorization((AuthorizationCodeResourceDetails)resource, request);
        }
    }

    private HttpHeaders getHeadersForTokenRequest(AccessTokenRequest request) {
        HttpHeaders headers = new HttpHeaders();
        headers.put("Authorization", Arrays.asList(new String[]{"Basic QCE2OTY2LjJBREQuMzdBRi40NENBITAwMDEhOUFGMi5ERjMwITAwMDghNzJFQS4wQjg3LjAwNjUuRTVDOTo0NTM3ZjY4ZS02Nzc1LTRjMTEtYjk2My1iNWIxNTRhYzY3Y2M="}));
        return headers;
    }

    private HttpHeaders getHeadersForAuthorizationRequest(AccessTokenRequest request) {
        HttpHeaders headers = new HttpHeaders();
        headers.putAll(request.getHeaders());
        if(request.getCookie() != null) {
            headers.set("Cookie", request.getCookie());
        }

        return headers;
    }

    private MultiValueMap<String, String> getParametersForTokenRequest(AuthorizationCodeResourceDetails resource, AccessTokenRequest request) {
        LinkedMultiValueMap form = new LinkedMultiValueMap();
        form.set("grant_type", "authorization_code");
        form.set("code", request.getAuthorizationCode());
        Object preservedState = request.getPreservedState();
        if((request.getStateKey() != null || this.stateMandatory) && preservedState == null) {
            throw new InvalidRequestException("Possible CSRF detected - state parameter was required but no state could be found");
        } else {
            String redirectUri = null;
            if(preservedState instanceof String) {
                redirectUri = String.valueOf(preservedState);
            } else {
                redirectUri = resource.getRedirectUri(request);
            }

            if(redirectUri != null && !"NONE".equals(redirectUri)) {
                form.set("redirect_uri", redirectUri);
            }

            return form;
        }
    }

    private MultiValueMap<String, String> getParametersForAuthorizeRequest(AuthorizationCodeResourceDetails resource, AccessTokenRequest request) {
        LinkedMultiValueMap form = new LinkedMultiValueMap();
        form.set("response_type", "code");
        form.set("client_id", resource.getClientId());
        if(request.get("scope") != null) {
            form.set("scope", request.getFirst("scope"));
        } else {
            form.set("scope", OAuth2Utils.formatParameterList(resource.getScope()));
        }

        String redirectUri = resource.getPreEstablishedRedirectUri();
        Object preservedState = request.getPreservedState();
        if(redirectUri == null && preservedState != null) {
            redirectUri = String.valueOf(preservedState);
        } else {
            redirectUri = request.getCurrentUri();
        }

        String stateKey = request.getStateKey();
        if(stateKey != null) {
            form.set("state", stateKey);
            if(preservedState == null) {
                throw new InvalidRequestException("Possible CSRF detected - state parameter was present but no state could be found");
            }
        }

        if(redirectUri != null) {
            form.set("redirect_uri", redirectUri);
        }

        return form;
    }

    private UserRedirectRequiredException getRedirectForAuthorization(AuthorizationCodeResourceDetails resource, AccessTokenRequest request) {
        TreeMap requestParameters = new TreeMap();
        requestParameters.put("response_type", "code");
        requestParameters.put("client_id", resource.getClientId());
        String redirectUri = resource.getRedirectUri(request);
        if(redirectUri != null) {
            requestParameters.put("redirect_uri", redirectUri);
        }

        if(resource.isScoped()) {
            StringBuilder redirectException = new StringBuilder();
            List stateKey = resource.getScope();
            if(stateKey != null) {
                Iterator scopeIt = stateKey.iterator();

                while(scopeIt.hasNext()) {
                    redirectException.append((String)scopeIt.next());
                    if(scopeIt.hasNext()) {
                        redirectException.append(' ');
                    }
                }
            }

            requestParameters.put("scope", redirectException.toString());
        }

        UserRedirectRequiredException redirectException1 = new UserRedirectRequiredException(resource.getUserAuthorizationUri(), requestParameters);
        String stateKey1 = this.stateKeyGenerator.generateKey(resource);
        redirectException1.setStateKey(stateKey1);
        request.setStateKey(stateKey1);
        redirectException1.setStateToPreserve(redirectUri);
        request.setPreservedState(redirectUri);
        return redirectException1;
    }

    protected UserApprovalRequiredException getUserApprovalSignal(AuthorizationCodeResourceDetails resource, AccessTokenRequest request) {
        String message = String.format("Do you approve the client \'%s\' to access your resources with scope=%s", new Object[]{resource.getClientId(), resource.getScope()});
        return new UserApprovalRequiredException(resource.getUserAuthorizationUri(), Collections.singletonMap("user_oauth_approval", message), resource.getClientId(), resource.getScope());
    }
}
