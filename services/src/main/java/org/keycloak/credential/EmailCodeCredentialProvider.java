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
package org.keycloak.credential;

import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.models.*;
import org.keycloak.models.cache.CachedUserModel;
import org.keycloak.models.cache.OnUserCache;
import org.keycloak.models.cache.UserCache;
import org.keycloak.models.utils.HmacOTP;
import org.keycloak.models.utils.TimeBasedOTP;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class EmailCodeCredentialProvider implements CredentialProvider, CredentialInputValidator, CredentialInputUpdater, OnUserCache {
    private static final Logger logger = Logger.getLogger(EmailCodeCredentialProvider.class);

    protected KeycloakSession session;

    protected List<CredentialModel> getCachedCredentials(UserModel user, String type) {
        if (!(user instanceof CachedUserModel)) return null;
        CachedUserModel cached = (CachedUserModel)user;
        if (cached.isMarkedForEviction()) return null;
        List<CredentialModel> rtn = (List<CredentialModel>)cached.getCachedWith().get(EmailCodeCredentialProvider.class.getName() + "." + type);
        if (rtn == null) return Collections.EMPTY_LIST;
        return rtn;
    }

    protected UserCredentialStore getCredentialStore() {
        return session.userCredentialManager();
    }

    @Override
    public void onCache(RealmModel realm, CachedUserModel user, UserModel delegate) {
        List<CredentialModel> creds = getCredentialStore().getStoredCredentialsByType(realm, user, CredentialModel.CODE);
        user.getCachedWith().put(EmailCodeCredentialProvider.class.getName() + "." + CredentialModel.CODE, creds);

    }

    public EmailCodeCredentialProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        if (!supportsCredentialType(input.getType())) return false;

        if (!(input instanceof UserCredentialModel)) {
            logger.debug("Expected instance of UserCredentialModel for CredentialInput");
            return false;
        }
        UserCredentialModel inputModel = (UserCredentialModel)input;
        List<CredentialModel> models = null;
        CredentialModel model = null;
        models = getCredentialStore().getStoredCredentialsByType(realm, user, CredentialModel.CODE);
        if (models == null || models.size() == 0) {
            // delete all existing
            disableCredentialType(realm, user, CredentialModel.CODE);
            model = new CredentialModel();
        } else {
            model = models.get(0);
        }
        model.setType(CredentialModel.CODE);
        model.setValue(inputModel.getValue());
        model.setPeriod(60);
        if (model.getId() == null) {
            getCredentialStore().createCredential(realm, user, model);
        } else {
            getCredentialStore().updateCredential(realm, user, model);
        }
        UserCache userCache = session.userCache();
        if (userCache != null) {
            userCache.evict(realm, user);
        }
        return true;



    }

    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {
        //TODO
    }

    @Override
    public Set<String> getDisableableCredentialTypes(RealmModel realm, UserModel user) {
        return Collections.EMPTY_SET;
    }


    @Override
    public boolean supportsCredentialType(String credentialType) {
        return CredentialModel.CODE.equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        if (!supportsCredentialType(credentialType)) return false;

        return !getCredentialStore().getStoredCredentialsByType(realm, user, CredentialModel.CODE).isEmpty();

    }

    public static boolean validOTP(RealmModel realm, String token, String secret) {
        OTPPolicy policy = realm.getOTPPolicy();
        if (policy.getType().equals(UserCredentialModel.TOTP)) {
            TimeBasedOTP validator = new TimeBasedOTP(policy.getAlgorithm(), policy.getDigits(), policy.getPeriod(), policy.getLookAheadWindow());
            return validator.validateTOTP(token, secret.getBytes());
        } else {
            HmacOTP validator = new HmacOTP(policy.getDigits(), policy.getAlgorithm(), policy.getLookAheadWindow());
            int c = validator.validateHOTP(token, secret, policy.getInitialCounter());
            return c > -1;
        }

    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        if (! (input instanceof UserCredentialModel)) {
            logger.debug("Expected instance of UserCredentialModel for CredentialInput");
            return false;

        }
        String token = ((UserCredentialModel) input).getValue();
        if (token == null) {
            return false;
        }
        List<CredentialModel> creds = getCachedCredentials(user, CredentialModel.CODE);
        if (creds == null) {
            creds = getCredentialStore().getStoredCredentialsByType(realm, user, CredentialModel.CODE);
        } else {
            logger.debugv("Cache hit for CODE for user {0}", user.getUsername());
        }
        for (CredentialModel cred : creds) {
            if (token.equals(cred.getValue())) {
                return true;
            }
        }
        return false;
    }
}
