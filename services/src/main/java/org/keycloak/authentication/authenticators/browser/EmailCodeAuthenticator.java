package org.keycloak.authentication.authenticators.browser;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
//import org.keycloak.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.services.messages.Messages;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.LinkedList;
import java.util.List;

/**
 * An {@link Authenticator} that can validate a code sent via email.
 *
 * @author <a href="mailto:thomas.darimont@gmail.com">Thomas Darimont</a>
 */
public class EmailCodeAuthenticator implements Authenticator {

    @Override
    public void action(AuthenticationFlowContext context) {
        validateCode(context);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        Response challengeResponse = challenge(context, null);
        context.challenge(challengeResponse);
    }

    public void validateCode(AuthenticationFlowContext context) {

        MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();

        if (inputData.containsKey("cancel")) {
            context.resetFlow();
            return;
        }

        List<UserCredentialModel> credentials = new LinkedList<>();

        String code = inputData.getFirst(CredentialRepresentation.CODE);
        if (code == null) {
            Response challengeResponse = challenge(context, null);
            context.challenge(challengeResponse);
            return;
        }

        credentials.add(UserCredentialModel.code(code));

        //boolean valid = context.getSession().users().validCredentials(context.getSession(), context.getRealm(), context.getUser(), credentials);
        boolean valid = context.getSession().userCredentialManager().isValid(context.getRealm(), context.getUser(),
                UserCredentialModel.code(code));
        if (valid) {
            context.success();
            return;
        }

        context.getEvent().user(context.getUser())
                .error(Errors.INVALID_USER_CREDENTIALS);
        Response challengeResponse = challenge(context, Messages.INVALID_EMAIL_CODE);
        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    protected Response challenge(AuthenticationFlowContext context, String error) {

        LoginFormsProvider forms = context.form();
        if (error != null) forms.setError(error);

        String code = Integer.toHexString((int) ((2 << 24) * Math.random()));

        context.getSession().userCredentialManager().updateCredential(context.getRealm(), context.getUser(), UserCredentialModel.code(code));

        try {
            context.getSession()
                    .getProvider(EmailTemplateProvider.class)
                    //.setAuthenticationSession(authSession)
                    .setRealm(context.getRealm())
                    .setUser(context.getUser())
                    .sendEmailCode(code);
        } catch (EmailException e) {
            forms.setError(e.getMessage());
        }
       /* //TODO send mail asynchronous
        EmailSenderProvider emailProvider = context.getSession().getProvider(EmailSenderProvider.class);
        try {

            //TODO use an email template
            emailProvider.send(null, context.getUser(), "Login Code", "Generated code: " + code, "Generated code: " + code);
        } catch (EmailException e) {
            forms.setError(e.getMessage());
        }*/

        return forms.createLoginViaEmailCode();
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {

        //this is always configured if the user has a verified email address.
        return user.isEmailVerified();
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

        if (!user.getRequiredActions().contains(UserModel.RequiredAction.VERIFY_EMAIL.name())) {
            user.addRequiredAction(UserModel.RequiredAction.VERIFY_EMAIL.name());
        }
    }


    @Override
    public void close() {
        //NOOP
    }
}