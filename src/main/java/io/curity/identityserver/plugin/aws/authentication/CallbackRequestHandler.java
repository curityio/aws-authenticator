/*
 *  Copyright 2017 Curity AB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package io.curity.identityserver.plugin.aws.authentication;

import io.curity.identityserver.plugin.authentication.DefaultOAuthClient;
import io.curity.identityserver.plugin.authentication.OAuthClient;
import io.curity.identityserver.plugin.authentication.ParamBuilder;
import io.curity.identityserver.plugin.aws.config.AWSAuthenticatorPluginConfig;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClientBuilder;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.curity.identityserver.sdk.attribute.Attribute;
import se.curity.identityserver.sdk.attribute.Attributes;
import se.curity.identityserver.sdk.attribute.AuthenticationAttributes;
import se.curity.identityserver.sdk.attribute.ContextAttributes;
import se.curity.identityserver.sdk.attribute.SubjectAttributes;
import se.curity.identityserver.sdk.authentication.AuthenticationResult;
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler;
import se.curity.identityserver.sdk.errors.ErrorCode;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.Json;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider;
import se.curity.identityserver.sdk.web.Request;
import se.curity.identityserver.sdk.web.Response;

import java.io.IOException;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

import static io.curity.identityserver.plugin.authentication.Constants.Params.*;
import static io.curity.identityserver.plugin.aws.authentication.Constants.*;
import static se.curity.identityserver.sdk.attribute.ContextAttributes.AUTH_TIME;
import static se.curity.identityserver.sdk.attribute.ContextAttributes.SCOPE;

public class CallbackRequestHandler
        implements AuthenticatorRequestHandler<CallbackGetRequestModel> {


    private static final Logger _logger = LoggerFactory.getLogger(CallbackRequestHandler.class);

    private final ExceptionFactory _exceptionFactory;
    private final OAuthClient _oauthClient;
    private final AWSAuthenticatorPluginConfig _config;
    private final HttpClient _client;

    public CallbackRequestHandler(ExceptionFactory exceptionFactory,
                                  AuthenticatorInformationProvider provider,
                                  Json json,
                                  AWSAuthenticatorPluginConfig config) {
        _exceptionFactory = exceptionFactory;
        _oauthClient = new DefaultOAuthClient(exceptionFactory, provider, json, config.getSessionManager());
        _client = HttpClientBuilder.create().build();
        _config = config;
    }

    @Override
    public CallbackGetRequestModel preProcess(Request request, Response response) {
        if (request.isGetRequest()) {
            return new CallbackGetRequestModel(request);
        } else {
            throw _exceptionFactory.methodNotAllowed();
        }
    }

    @Override
    public Optional<AuthenticationResult> get(CallbackGetRequestModel requestModel,
                                              Response response) {
        _oauthClient.redirectToAuthenticationOnError(requestModel.getRequest(), _config.id());

        Map<String, Object> tokenMap = getTokens(_config.getDomain() + _config.getTokenEndpoint().toString(),
                _config.getClientId(),
                _config.getClientSecret(),
                requestModel.getCode(),
                requestModel.getState());

        try {
            //parse claims without need of key
            Map claimsMap = new JwtConsumerBuilder().setSkipAllValidators().setDisableRequireSignature().setSkipSignatureVerification().build().processToClaims(tokenMap.get(ID_TOKEN).toString()).getClaimsMap();

            String userId = claimsMap.get(USERNAME).toString();

            Attributes subjectAttributes = Attributes.of(Attribute.of(USERNAME, userId), Attribute.of(EMAIL, claimsMap.get(EMAIL).toString()));
            Attributes contextAttributes = Attributes.of(Attribute.of(PARAM_ACCESS_TOKEN, tokenMap.get(PARAM_ACCESS_TOKEN).toString()),
                    Attribute.of(AUTH_TIME, Long.valueOf(claimsMap.get(AUTH_TIME).toString())),
                    Attribute.of(EMAIL_VERIFIED, Boolean.valueOf(claimsMap.get(EMAIL_VERIFIED).toString())));
            AuthenticationAttributes attributes = AuthenticationAttributes.of(
                    SubjectAttributes.of(userId, subjectAttributes),
                    ContextAttributes.of(contextAttributes));
            AuthenticationResult authenticationResult = new AuthenticationResult(attributes);
            return Optional.ofNullable(authenticationResult);
        } catch (Exception e) {
            throw _exceptionFactory.internalServerException(ErrorCode.EXTERNAL_SERVICE_ERROR, "Invalid token " + e.getMessage());
        }
    }

    @Override
    public Optional<AuthenticationResult> post(CallbackGetRequestModel requestModel,
                                               Response response) {
        throw _exceptionFactory.methodNotAllowed();
    }

    public Map<String, Object> getTokens(String tokenEndpoint, String clientId, String clientSecret, String code, String state) {

        _oauthClient.validateState(state);

        try {
            ParamBuilder postData = new ParamBuilder();
            postData.addPair(PARAM_CODE, code)
                    .addPair(PARAM_GRANT_TYPE, PARAM_GRANT_TYPE_AUTHORIZATION_CODE)
                    .addPair(SCOPE, AWSAuthenticatorRequestHandler.getScope(_config))
                    .addPair(PARAM_REDIRECT_URI, _oauthClient.getCallbackUrl());
            UrlEncodedFormEntity data = new UrlEncodedFormEntity(postData.getPairs());

            HttpPost post = new HttpPost(tokenEndpoint);
            post.addHeader(HttpHeaders.CONTENT_TYPE, CONTENT_TYPE);
            post.setHeader(HttpHeaders.AUTHORIZATION, "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes()));
            post.setEntity(data);

            HttpResponse response = _client.execute(post);
            if (response.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
                _logger.debug("Got error response from token endpoint {}", response.getStatusLine());

                throw _exceptionFactory.internalServerException(ErrorCode.INVALID_SERVER_STATE, "INTERNAL SERVER ERROR");
            }

            return _oauthClient.parseResponse(response);
        } catch (IOException e) {
            _logger.warn("Could not communicate with token endpoint", e);

            throw _exceptionFactory.internalServerException(ErrorCode.EXTERNAL_SERVICE_ERROR, "Authentication failed");
        }
    }
}
