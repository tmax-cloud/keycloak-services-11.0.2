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

import okhttp3.Challenge;
import org.jboss.resteasy.specimpl.MultivaluedMapImpl;
import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class UsernamePasswordForm extends AbstractUsernameFormAuthenticator implements Authenticator {
    protected static ServicesLogger log = ServicesLogger.LOGGER;

    @Override
    public void action(AuthenticationFlowContext context) {

        //FIXME: by taegeon_woo
        HttpRequest request = context.getHttpRequest();
        if ( request.getDecodedFormParameters()!= null && request.getDecodedFormParameters().getFirst("isBrokerLogin")!= null ) {
            log.debug("From Info PopUp!!!!");
            context.success();
            return;
        }

        if ( context.getAuthenticationSession().getAuthNote("isBrokerLogin") != null
                && context.getAuthenticationSession().getAuthNote("isBrokerLogin").equalsIgnoreCase("true") ){
            log.debug("From broker login!!!!");
            context.form().setAttribute("isBrokerLogin", "true");
        }
        if (context.getUser() != null){
            context.form().setAttribute("email", context.getUser().getEmail());
        }

        if ( request.getDecodedFormParameters()!= null && request.getDecodedFormParameters().getFirst(AuthenticationManager.FORM_REMEMBER_EMAIL)!= null
                && request.getDecodedFormParameters().getFirst(AuthenticationManager.FORM_REMEMBER_EMAIL).equalsIgnoreCase("on")
                && request.getDecodedFormParameters().getFirst(AuthenticationManager.FORM_USERNAME)!= null
                && request.getDecodedFormParameters().getFirst(AuthenticationManager.FORM_USERNAME) != "") {
            AuthenticationManager.createRememberEmailCookie(context.getRealm(), request.getDecodedFormParameters().getFirst(AuthenticationManager.FORM_USERNAME), context.getUriInfo(), context.getConnection());
            context.form().setAttribute(AuthenticationManager.FORM_REMEMBER_EMAIL, request.getDecodedFormParameters().getFirst(AuthenticationManager.FORM_USERNAME));
        } else{
            AuthenticationManager.expireRememberEmailCookie(context.getRealm(), context.getUriInfo(), context.getConnection());
        }
        //FIXME: by taegeon_woo

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel")) {
            context.cancelLogin();
            return;
        }
        if (!validateForm(context, formData)) {
            return;
        }

        //FIXME: by taegeon_woo
        if ( context.getAuthenticationSession().getAuthNote("isBrokerLogin") != null
                && context.getAuthenticationSession().getAuthNote("isBrokerLogin").equalsIgnoreCase("true") ){
            log.debug("From broker login!! direct to LinkSuccess Page");
            String accessCode = context.generateAccessCode();
            Response challenge = context.form().setStatus(Response.Status.OK)
                    .setSuccess(Messages.IDENTITY_PROVIDER_LINK_SUCCESS, context.getAuthenticationSession().getAuthNote("brokerVendor"), context.getAuthenticationSession().getAuthNote("brokerEmail"))
                    .setAttribute(Constants.SKIP_LINK, true)
                    .setAttribute(Constants.TEMPLATE_ATTR_ACTION_URI, context.getActionUrl(accessCode))
                    .setAttribute("identityProviderVendor", context.getAuthenticationSession().getAuthNote("brokerVendor"))
                    .setAttribute("identityProviderUserName", context.getAuthenticationSession().getAuthNote("brokerEmail"))
                    .setAttribute("hyperauthUserName", context.getUser().getEmail())
                    .createInfoPage();
            context.challenge(challenge);
            return;
        }
        //FIXME: by taegeon_woo

        context.success();
    }

    protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        return validateUserAndPassword(context, formData);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
        String loginHint = context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);

        String rememberMeUsername = AuthenticationManager.getRememberMeUsername(context.getRealm(), context.getHttpRequest().getHttpHeaders());

        if (loginHint != null || rememberMeUsername != null) {
            if (loginHint != null) {
                formData.add(AuthenticationManager.FORM_USERNAME, loginHint);
            } else {
                formData.add(AuthenticationManager.FORM_USERNAME, rememberMeUsername);
                formData.add("rememberMe", "on");
            }
        }

        //FIXME: by taegeon_woo
        String remeberEmailUsername = AuthenticationManager.getRememberEmailUsername(context.getRealm(), context.getHttpRequest().getHttpHeaders());
        if (remeberEmailUsername != null) {
            log.debug("remeberEmailUsername :" + remeberEmailUsername);
            context.form().setAttribute(AuthenticationManager.FORM_REMEMBER_EMAIL, remeberEmailUsername);
        }
        //FIXME: by taegeon_woo

        Response challengeResponse = challenge(context, formData);
        context.challenge(challengeResponse);
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        LoginFormsProvider forms = context.form();

        if (formData.size() > 0) forms.setFormData(formData);

        return forms.createLoginUsernamePassword();
    }


    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        // never called
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // never called
    }

    @Override
    public void close() {

    }

}
