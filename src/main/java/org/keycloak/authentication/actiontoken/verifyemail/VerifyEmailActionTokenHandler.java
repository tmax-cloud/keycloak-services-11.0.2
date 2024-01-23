/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.authentication.actiontoken.verifyemail;

import org.keycloak.authentication.actiontoken.AbstractActionTokenHander;
import org.keycloak.TokenVerifier.Predicate;
import org.keycloak.authentication.actiontoken.*;
import org.keycloak.events.*;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserModel.RequiredAction;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionCompoundId;
import org.keycloak.sessions.AuthenticationSessionModel;
import java.util.Objects;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

/**
 * Action token handler for verification of e-mail address.
 * @author hmlnarik
 */
public class VerifyEmailActionTokenHandler extends AbstractActionTokenHander<VerifyEmailActionToken> {

    public VerifyEmailActionTokenHandler() {
        super(
          VerifyEmailActionToken.TOKEN_TYPE,
          VerifyEmailActionToken.class,
          Messages.STALE_VERIFY_EMAIL_LINK,
          EventType.VERIFY_EMAIL,
          Errors.INVALID_TOKEN
        );
    }

    @Override
    public Predicate<? super VerifyEmailActionToken>[] getVerifiers(ActionTokenContext<VerifyEmailActionToken> tokenContext) {
        return TokenUtils.predicates(
          TokenUtils.checkThat(
            t -> Objects.equals(t.getEmail(), tokenContext.getAuthenticationSession().getAuthenticatedUser().getEmail()),
            Errors.INVALID_EMAIL, getDefaultErrorMessage()
          )
        );
    }

    @Override
    public Response handleToken(VerifyEmailActionToken token, ActionTokenContext<VerifyEmailActionToken> tokenContext) {
        UserModel user = tokenContext.getAuthenticationSession().getAuthenticatedUser();
        EventBuilder event = tokenContext.getEvent();

        event.event(EventType.VERIFY_EMAIL).detail(Details.EMAIL, user.getEmail());

        AuthenticationSessionModel authSession = tokenContext.getAuthenticationSession();
        final UriInfo uriInfo = tokenContext.getUriInfo();
        final RealmModel realm = tokenContext.getRealm();
        final KeycloakSession session = tokenContext.getSession();

        if (tokenContext.isAuthenticationSessionFresh()) {
            // Update the authentication session in the token
            token.setCompoundOriginalAuthenticationSessionId(token.getCompoundAuthenticationSessionId());

            String authSessionEncodedId = AuthenticationSessionCompoundId.fromAuthSession(authSession).getEncodedId();
            token.setCompoundAuthenticationSessionId(authSessionEncodedId);
            UriBuilder builder = Urls.actionTokenBuilder(uriInfo.getBaseUri(), token.serialize(session, realm, uriInfo),
                    authSession.getClient().getClientId(), authSession.getTabId());
            String confirmUri = builder.build(realm.getName()).toString();

            return session.getProvider(LoginFormsProvider.class)
                    .setAuthenticationSession(authSession)
                    .setSuccess(Messages.CONFIRM_EMAIL_ADDRESS_VERIFICATION, user.getEmail())
                    .setAttribute(Constants.TEMPLATE_ATTR_ACTION_URI, confirmUri)
                    .createInfoPage();
        }

        // verify user email as we know it is valid as this entry point would never have gotten here.
        user.setEmailVerified(true);
        user.removeRequiredAction(RequiredAction.VERIFY_EMAIL);
        authSession.removeRequiredAction(RequiredAction.VERIFY_EMAIL);

        event.success();

        //FIXME: by taegeon_woo 명확히 이유 파악은 아직 덜됐지만, tokenContext.isAuthenticationSessionFresh()가 true 인 경우는, 세션에든, 쿠키에든 sessionID가 남아있지 않아서 token context에 AuthentiactionSession을 수동으로 fresh 하게 set해주었을때 이고
        //FIXME : 그런 경우에 이메일 인증 완료 페이지가 뜨게끔 되어있는데 ( 아마도 이메일 인증을 아예 다른 컴퓨터에서 할 가능성도 있음 --> 이 경우에 시간이 흘렀던, 다른 기기에 의해서든 authentication session은 없을 가능성이 높음.
        //FIXME : 다른 required action은 제대로 동작하지 않을 가능성 여전히 내포함.
        token.setCompoundOriginalAuthenticationSessionId(token.getCompoundAuthenticationSessionId());
        //FIXME: by taegeon_woo

        if (token.getCompoundOriginalAuthenticationSessionId() != null) {
            //FIXME: by taegeon_woo
//            AuthenticationSessionManager asm = new AuthenticationSessionManager(tokenContext.getSession());
//            asm.removeAuthenticationSession(tokenContext.getRealm(), authSession, true);
            //FIXME: by taegeon_woo

            return tokenContext.getSession().getProvider(LoginFormsProvider.class)
                    .setAuthenticationSession(authSession)
                    //FIXME: by taegeon_woo
                    .setAttribute("brokerVendor", tokenContext.getAuthenticationSession().getAuthNote("brokerVendor"))
                    .setAttribute("brokerEmail", tokenContext.getAuthenticationSession().getAuthNote("brokerEmail"))
                    .setAttribute("isBrokerLogin", tokenContext.getAuthenticationSession().getAuthNote("isBrokerLogin"))
                    //FIXME: by taegeon_woo
                    .setSuccess(Messages.EMAIL_VERIFIED)
                    .createInfoPage();
        }

        tokenContext.setEvent(event.clone().removeDetail(Details.EMAIL).event(EventType.LOGIN));

        String nextAction = AuthenticationManager.nextRequiredAction(session, authSession, tokenContext.getClientConnection(), tokenContext.getRequest(), uriInfo, event);
        return AuthenticationManager.redirectToRequiredActions(session, realm, authSession, uriInfo, nextAction);
    }

}
