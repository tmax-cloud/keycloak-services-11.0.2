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

package org.keycloak.authentication.requiredactions;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.*;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.PasswordCredentialProvider;
import org.keycloak.credential.PasswordCredentialProviderFactory;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.ModelException;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.concurrent.TimeUnit;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class UpdatePassword implements RequiredActionProvider, RequiredActionFactory, DisplayTypeRequiredActionFactory {
    private static final Logger logger = Logger.getLogger(UpdatePassword.class);
    
    @Override
    public InitiatedActionSupport initiatedActionSupport() {
        return InitiatedActionSupport.SUPPORTED;
    }
    
    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        int daysToExpirePassword = context.getRealm().getPasswordPolicy().getDaysToExpirePassword();
        //FIXME: by taegeon_woo
//        if(daysToExpirePassword != -1) {
        if(daysToExpirePassword != -1
                && !(context.getAuthenticationSession().getAuthNote("passwordUpdateSkip") != null
                        && context.getAuthenticationSession().getAuthNote("passwordUpdateSkip").equalsIgnoreCase("t"))) {
        //FIXME: by taegeon_woo
            PasswordCredentialProvider passwordProvider = (PasswordCredentialProvider)context.getSession().getProvider(CredentialProvider.class, PasswordCredentialProviderFactory.PROVIDER_ID);
            CredentialModel password = passwordProvider.getPassword(context.getRealm(), context.getUser());
            if (password != null) {
                if(password.getCreatedDate() == null) {
                    context.getUser().addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
                    logger.debug("User is required to update password");
                } else {
                    long timeElapsed = Time.toMillis(Time.currentTime()) - password.getCreatedDate();
                    long timeToExpire = TimeUnit.DAYS.toMillis(daysToExpirePassword);

                    if(timeElapsed > timeToExpire) {
                        context.getUser().addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
                        logger.debug("User is required to update password");
                    }
                }
            }
        }
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        //FIXME: by taegeon_woo
        logger.info("User [ " + context.getUser().getUsername() + " ] Need to Update Password");
        Response challenge = context.form().createForm("login-update-password-choose.ftl");
        context.challenge(challenge);
//        Response challenge = context.form()
//                .setAttribute("username", context.getAuthenticationSession().getAuthenticatedUser().getUsername())
//                .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
//        context.challenge(challenge);
        //FIXME: by taegeon_woo
    }

    @Override
    public void processAction(RequiredActionContext context) {
        EventBuilder event = context.getEvent();
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        //FIXME: by taegeon_woo
        String skip = formData.getFirst("passwordUpdateSkip");
        if (skip != null && skip.equalsIgnoreCase("t")) {
            // 다음에 변경하기 클릭시
            logger.info("User [ " + context.getUser().getUsername() + " ] Skip Password Update !");
            logger.info("User [ " + context.getUser().getUsername() + " ] Ask Again Later");
            context.getAuthenticationSession().setAuthNote("passwordUpdateSkip", "t");
            context.success();
            return;

        } else if (skip != null && skip.equalsIgnoreCase("f")){
            // 변경하기 클릭시, 비밀번호 변경 페이지를 던진다.
            Response challenge = context.form()
                .setAttribute("username", context.getAuthenticationSession().getAuthenticatedUser().getUsername())
                .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
            if(context.getAuthenticationSession().getAuthNote("passwordUpdateSkip") != null){
                context.getAuthenticationSession().removeAuthNote("passwordUpdateSkip");
            }
            context.challenge(challenge);
            return;
        }
        //FIXME: by taegeon_woo

        event.event(EventType.UPDATE_PASSWORD);
        String passwordNew = formData.getFirst("password-new");
        String passwordConfirm = formData.getFirst("password-confirm");

        EventBuilder errorEvent = event.clone().event(EventType.UPDATE_PASSWORD_ERROR)
                .client(context.getAuthenticationSession().getClient())
                .user(context.getAuthenticationSession().getAuthenticatedUser());

        if (Validation.isBlank(passwordNew)) {
            Response challenge = context.form()
                    .setAttribute("username", context.getAuthenticationSession().getAuthenticatedUser().getUsername())
                    .setError(Messages.MISSING_PASSWORD)
                    .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
            context.challenge(challenge);
            errorEvent.error(Errors.PASSWORD_MISSING);
            return;
        } else if (!passwordNew.equals(passwordConfirm)) {
            Response challenge = context.form()
                    .setAttribute("username", context.getAuthenticationSession().getAuthenticatedUser().getUsername())
                    .setError(Messages.NOTMATCH_PASSWORD)
                    .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
            context.challenge(challenge);
            errorEvent.error(Errors.PASSWORD_CONFIRM_ERROR);
            return;

        //FIXME : by taegeon_woo
        } else if (sameWithOldPW(context.getSession(), context.getAuthenticationSession().getAuthenticatedUser().getUsername(), passwordNew)){
            Response challenge = context.form()
                    .setAttribute("username", context.getAuthenticationSession().getAuthenticatedUser().getUsername())
                    .setError(Messages.SAME_PASSWORD)
                    .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
            context.challenge(challenge);
            errorEvent.error(Errors.PASSWORD_REJECTED);
            return;
        }
        //FIXME : by taegeon_woo

        try {
            context.getSession().userCredentialManager().updateCredential(context.getRealm(), context.getUser(), UserCredentialModel.password(passwordNew, false));
            context.success();
        } catch (ModelException me) {
            errorEvent.detail(Details.REASON, me.getMessage()).error(Errors.PASSWORD_REJECTED);
            Response challenge = context.form()
                    .setAttribute("username", context.getAuthenticationSession().getAuthenticatedUser().getUsername())
                    .setError(me.getMessage(), me.getParameters())
                    .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
            context.challenge(challenge);
            return;
        } catch (Exception ape) {
            errorEvent.detail(Details.REASON, ape.getMessage()).error(Errors.PASSWORD_REJECTED);
            Response challenge = context.form()
                    .setAttribute("username", context.getAuthenticationSession().getAuthenticatedUser().getUsername())
                    .setError(ape.getMessage())
                    .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
            context.challenge(challenge);
            return;
        }
    }
    
    //FIXME : by taegeon_woo
    private boolean sameWithOldPW(KeycloakSession session, String username, String password) {
        UserCredentialModel cred = UserCredentialModel.password(password);
        if (session.userCredentialManager().isValid(session.getContext().getRealm(), session.users().getUserByUsername(username, session.getContext().getRealm()), cred)) {
            return true;
        } else {
            return false;
        }
    }
    //FIXME : by taegeon_woo

    @Override
    public void close() {

    }

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return this;
    }


    @Override
    public RequiredActionProvider createDisplay(KeycloakSession session, String displayType) {
        if (displayType == null) return this;
        if (!OAuth2Constants.DISPLAY_CONSOLE.equalsIgnoreCase(displayType)) return null;
        return ConsoleUpdatePassword.SINGLETON;
    }


    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getDisplayText() {
        return "Update Password";
    }


    @Override
    public String getId() {
        return UserModel.RequiredAction.UPDATE_PASSWORD.name();
    }

    @Override
    public boolean isOneTimeAction() {
        return true;
    }
}
