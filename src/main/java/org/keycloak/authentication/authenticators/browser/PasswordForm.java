/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.authentication.authenticators.browser;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.authentication.authenticators.broker.IdpReviewProfileAuthenticator;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.PasswordCredentialProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.messages.Messages;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

public class PasswordForm extends UsernamePasswordForm implements CredentialValidator<PasswordCredentialProvider> {

    protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        return validatePassword(context, context.getUser(), formData, false);
    }

    private static final Logger logger = Logger.getLogger(PasswordForm.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        // FIXME :  delete
        if(context.getAuthenticationSession().getAuthNote("selection")!= null) {
            logger.debug(" context.getAuthenticationSession().getAuthNote(\"selection\") : " + context.getAuthenticationSession().getAuthNote("selection"));
            if (!context.getAuthenticationSession().getAuthNote("selection").equals("password")){
                context.success();
                return;
            }
        }

        if ( context.getAuthenticationSession().getAuthNote("isBrokerLogin") != null
                && context.getAuthenticationSession().getAuthNote("isBrokerLogin").equalsIgnoreCase("true") ){
            logger.info("From broker login!!!!");
            context.form().setAttribute("isBrokerLogin", "true");
        }
        context.form().setAttribute("email", context.getUser().getEmail());

        // FIXME :  delete
        Response challengeResponse = context.form().createLoginPassword();
        context.challenge(challengeResponse);
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        // never called
        return getCredentialProvider(session).isConfiguredFor(realm, user, getType(session));
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    protected Response createLoginForm(LoginFormsProvider form) {
        return form.createLoginPassword();
    }

    @Override
    protected String getDefaultChallengeMessage(AuthenticationFlowContext context) {
        return Messages.INVALID_PASSWORD;
    }

    @Override
    public PasswordCredentialProvider getCredentialProvider(KeycloakSession session) {
        return (PasswordCredentialProvider)session.getProvider(CredentialProvider.class, "keycloak-password");
    }
}
