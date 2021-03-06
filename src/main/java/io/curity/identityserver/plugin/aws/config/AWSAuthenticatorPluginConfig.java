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

package io.curity.identityserver.plugin.aws.config;

import se.curity.identityserver.sdk.config.Configuration;
import se.curity.identityserver.sdk.config.annotation.DefaultBoolean;
import se.curity.identityserver.sdk.config.annotation.DefaultString;
import se.curity.identityserver.sdk.config.annotation.Description;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.HttpClient;
import se.curity.identityserver.sdk.service.Json;
import se.curity.identityserver.sdk.service.SessionManager;
import se.curity.identityserver.sdk.service.WebServiceClientFactory;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider;

import java.net.URI;
import java.util.Optional;

@SuppressWarnings("InterfaceNeverImplemented")
public interface AWSAuthenticatorPluginConfig extends Configuration
{

    @Description("Custom URL to your app (e.g: https://mydomain.auth.some-region.amazoncognito.com)")
    URI getDomain();

    @Description("Client id")
    String getClientId();

    @Description("Secret key used for communication with Amazon Cognito")
    String getClientSecret();

    @Description("Request a scope (email) that grants access to the email and email_verified info.")
    @DefaultBoolean(false)
    Boolean isEmail();

    @Description("Request a scope (phone) that grants access to the phone_number and phone_number_verified info.")
    @DefaultBoolean(false)
    Boolean isPhone();

    @Description("Request a scope (profile) that grants access to all user attributes that are readable by the client.")
    @DefaultBoolean(false)
    Boolean isProfile();

    @Description("Request a scope (aws.cognito.signin.user.admin) that grants access to Amazon Cognito User Pool API operations that require access tokens, such as UpdateUserAttributes and VerifyUserAttribute.")
    @DefaultBoolean(false)
    Boolean isAmazonCognitoUserPoolAccess();


    @Description("The HTTP client with any proxy and TLS settings that will be used to connect to Amazon Cognito")
    Optional<HttpClient> getHttpClient();

    SessionManager getSessionManager();

    ExceptionFactory getExceptionFactory();

    AuthenticatorInformationProvider getAuthenticatorInformationProvider();

    WebServiceClientFactory getWebServiceClientFactory();

    Json getJson();

}
