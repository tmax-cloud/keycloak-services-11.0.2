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

package org.keycloak.forms.account.freemarker.model;

import org.jboss.logging.Logger;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import javax.ws.rs.core.MultivaluedMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
//FIXME: by taegeon_woo Total Class
/**
 * @author <a href="mailto:taegeon_woo@tmax.co.kr">taegeon_woo</a>
 */
public class AdditionalAuthBean {

    private static final Logger logger = Logger.getLogger(AdditionalAuthBean.class);

    private final UserModel user;
    private final KeycloakSession session;
    private RealmModel realm;


    // TODO: More proper multi-value attribute support
    private final Map<String, String> attributes = new HashMap<>();

    public AdditionalAuthBean(UserModel user, KeycloakSession session, RealmModel realm) {
        this.user = user;
        this.session = session;
        this.realm = realm;
        for (Map.Entry<String, List<String>> attr : user.getAttributes().entrySet()) {
            List<String> attrValue = attr.getValue();
            if (attrValue.size() > 0) {
                attributes.put(attr.getKey(), attrValue.get(0));
            }

            if (attrValue.size() > 1) {
                logger.warnf("There are more values for attribute '%s' of user '%s' . Will display just first value", attr.getKey(), user.getUsername());
            }
        }
    }

    public boolean isEmailOtpEnable(){
        if (user.getAttribute("otpEnable")!= null && user.getAttribute("otpEnable").size() > 0
                && user.getAttribute("otpEnable").get(0).equalsIgnoreCase("true")){
            return true;
        }
        return false;
    }

    public boolean isSimpleLoginEnable(){
        if (user.getRequiredActions().contains("webauthn-register-passwordless")
                || ( session.userCredentialManager().getStoredCredentialsByType(realm, user, "webauthn-passwordless")!= null
                && session.userCredentialManager().getStoredCredentialsByType(realm, user, "webauthn-passwordless").size() > 0) ){
            return true;
        }
        return false;
    }
}
