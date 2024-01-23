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

package org.keycloak.authentication.authenticators.broker;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.broker.util.ExistingUserInfo;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.messages.Messages;

import javax.ws.rs.core.Response;
import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class IdpCreateUserIfUniqueAuthenticator extends AbstractIdpAuthenticator {

    private static Logger logger = Logger.getLogger(IdpCreateUserIfUniqueAuthenticator.class);


    @Override
    protected void actionImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {
    }

    @Override
    protected void authenticateImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {

        System.out.println("IdpCreateUserIfUniqueAuthenticator.authenticateImpl");
        logger.debug("initiate idpCreateUserIfUnique authenticator");
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();

        if (context.getAuthenticationSession().getAuthNote(EXISTING_USER_INFO) != null) {
            context.attempted();
            return;
        }

        if(context.getUser() != null){

            if(context.getUser().getUsername() != null){
                String authFlowCtxUserName = context.getUser().getUsername();
                logger.debug("authFlowCtxUserName: " + authFlowCtxUserName);
            }
            if(context.getUser().getLastName() != null){
                String authFlowCtxUserLastName = context.getUser().getLastName();
                logger.debug("authFlowCtxUserLastName: " + authFlowCtxUserLastName);
            }
            if(context.getUser().getFirstName() != null){
                String authFlowCtxUserFirstName = context.getUser().getFirstName();
                logger.debug("authFlowCtxUserFirstName: " + authFlowCtxUserFirstName);
            }
            if(context.getUser().getEmail() != null){
                String authFlowCtxUserEmail = context.getUser().getEmail();
                logger.debug("authFlowCtxUserEmail: " + authFlowCtxUserEmail);
            }
        }else{
            logger.debug("context.getUser() is null");
        }

        if (brokerContext.getUsername() != null){
            String brokeredCtxUserName = brokerContext.getUsername();
            logger.debug("brokeredCtxUserName: " + brokeredCtxUserName);
        }
        if (brokerContext.getLastName() != null){
            String brokeredCtxUserLastName = brokerContext.getLastName();
            logger.debug("brokeredCtxUserLastName: " + brokeredCtxUserLastName);
        }
        if (brokerContext.getFirstName() != null){
            String brokeredCtxUserFirstName = brokerContext.getFirstName();
            logger.debug("brokeredCtxUserFirstName: " + brokeredCtxUserFirstName);
        }
        if (brokerContext.getEmail() != null){
            String brokeredCtxUserEmail = brokerContext.getEmail();
            logger.debug("brokeredCtxUserEmail: " + brokeredCtxUserEmail);
        }

        if(serializedCtx.getUsername() != null){
            String serializedCtxUserName = serializedCtx.getUsername();
            logger.debug("serializedCtxUserName: " + serializedCtxUserName);
        }
        if(serializedCtx.getLastName() != null){
            String serializedCtxUserLastName = serializedCtx.getLastName();
            logger.debug("serializedCtxUserLastName: " + serializedCtxUserLastName);
        }
        if(serializedCtx.getFirstName() != null){
            String serializedCtxUserFirstName = serializedCtx.getFirstName();
            logger.debug("serializedCtxUserFirstName: " + serializedCtxUserFirstName);
        }
        if(serializedCtx.getEmail() != null){
            String serializedCtxUserEmail = serializedCtx.getEmail();
            logger.debug("serializedCtxUserEmail: " + serializedCtxUserEmail);
        }

        String username = getUsername(context, serializedCtx, brokerContext);
        if (username == null) {
            ServicesLogger.LOGGER.resetFlow(realm.isRegistrationEmailAsUsername() ? "Email" : "Username");
            context.getAuthenticationSession().setAuthNote(ENFORCE_UPDATE_PROFILE, "true");
            context.resetFlow();
            return;
        }

        ExistingUserInfo duplication = checkExistingUser(context, username, serializedCtx, brokerContext);

        if (duplication == null) {
            logger.debugf("No duplication detected!!! Creating account for user '%s' and linking with identity provider '%s' .",
                    username, brokerContext.getIdpConfig().getAlias());

            UserModel federatedUser = session.users().addUser(realm, username);
            federatedUser.setEnabled(true);

            //TODO : serialize에서 username만 뺴고 federatedUser에 다 넣어주고 있따.
            /*
            federatedUser는 idp유저고 실제 유저는 userEntity인데 이 둘이 연결된다
            userEntity에 last name, first name 을 넣어야 하는데 안들어가고 있고, federatedUser에 들어간 값이 나중에
            userEntity에서 update쳐지는것
            해결 -> 최초 USERENTITY에다 저장할때 넣어주고, UPDATE는 안해준다
             */

            for (Map.Entry<String, List<String>> attr : serializedCtx.getAttributes().entrySet()) {
                if (!UserModel.USERNAME.equalsIgnoreCase(attr.getKey())) {
                    federatedUser.setAttribute(attr.getKey(), attr.getValue());
                }
            }

            AuthenticatorConfigModel config = context.getAuthenticatorConfig();
            if (config != null && Boolean.parseBoolean(config.getConfig().get(IdpCreateUserIfUniqueAuthenticatorFactory.REQUIRE_PASSWORD_UPDATE_AFTER_REGISTRATION))) {
                logger.debugf("User '%s' required to update password", federatedUser.getUsername());
                federatedUser.addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
            }

            userRegisteredSuccess(context, federatedUser, serializedCtx, brokerContext);

            context.setUser(federatedUser);
            context.getAuthenticationSession().setAuthNote(BROKER_REGISTERED_NEW_USER, "true");
            context.success();
        } else {
            logger.debugf("Duplication detected. There is already existing user with %s '%s' .",
                    duplication.getDuplicateAttributeName(), duplication.getDuplicateAttributeValue());

            // Set duplicated user, so next authenticators can deal with it
            context.getAuthenticationSession().setAuthNote(EXISTING_USER_INFO, duplication.serialize());
            //Only show error message if the authenticator was required
            if (context.getExecution().isRequired()) {
                Response challengeResponse = context.form()
                        .setError(Messages.FEDERATED_IDENTITY_EXISTS, duplication.getDuplicateAttributeName(), duplication.getDuplicateAttributeValue())
                        .createErrorPage(Response.Status.CONFLICT);
                context.challenge(challengeResponse);
                context.getEvent()
                        .user(duplication.getExistingUserId())
                        .detail("existing_" + duplication.getDuplicateAttributeName(), duplication.getDuplicateAttributeValue())
                        .removeDetail(Details.AUTH_METHOD)
                        .removeDetail(Details.AUTH_TYPE)
                        .error(Errors.FEDERATED_IDENTITY_EXISTS);
            } else {
                context.attempted();
            }
        }
    }

    // Could be overriden to detect duplication based on other criterias (firstName, lastName, ...)
    protected ExistingUserInfo checkExistingUser(AuthenticationFlowContext context, String username, SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {

        if (brokerContext.getEmail() != null && !context.getRealm().isDuplicateEmailsAllowed()) {
            UserModel existingUser = context.getSession().users().getUserByEmail(brokerContext.getEmail(), context.getRealm());
            if (existingUser != null) {
                return new ExistingUserInfo(existingUser.getId(), UserModel.EMAIL, existingUser.getEmail());
            }
        }

        UserModel existingUser = context.getSession().users().getUserByUsername(username, context.getRealm());
        if (existingUser != null) {
            return new ExistingUserInfo(existingUser.getId(), UserModel.USERNAME, existingUser.getUsername());
        }

        return null;
    }

    protected String getUsername(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {
        RealmModel realm = context.getRealm();
        return realm.isRegistrationEmailAsUsername() ? brokerContext.getEmail() : brokerContext.getModelUsername();
    }


    // Empty method by default. This exists, so subclass can override and add callback after new user is registered through social
    protected void userRegisteredSuccess(AuthenticationFlowContext context, UserModel registeredUser, SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {

    }


    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

}
