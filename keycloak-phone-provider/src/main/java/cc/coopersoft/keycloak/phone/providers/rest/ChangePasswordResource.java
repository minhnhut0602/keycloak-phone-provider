package cc.coopersoft.keycloak.phone.providers.rest;

import cc.coopersoft.keycloak.phone.Utils;
import cc.coopersoft.keycloak.phone.authentication.forms.SupportPhonePages;
import cc.coopersoft.keycloak.phone.credential.PhoneOtpCredentialModel;
import cc.coopersoft.keycloak.phone.providers.constants.TokenCodeType;
import cc.coopersoft.keycloak.phone.providers.exception.PhoneNumberInvalidException;
import cc.coopersoft.keycloak.phone.providers.representations.PhoneUserRepresentation;
import cc.coopersoft.keycloak.phone.providers.representations.TokenCodeRepresentation;
import cc.coopersoft.keycloak.phone.providers.spi.PhoneVerificationCodeProvider;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.Config;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.hash.AbstractPbkdf2PasswordHashProviderFactory;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.credential.hash.PasswordHashSpi;
import org.keycloak.credential.hash.Pbkdf2Sha256PasswordHashProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.dto.OTPSecretData;
import org.keycloak.services.validation.Validation;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

import java.io.IOException;
import java.util.Optional;

import static jakarta.ws.rs.core.MediaType.APPLICATION_JSON;

public class ChangePasswordResource {

    private static final Logger logger = Logger.getLogger(ChangePasswordResource.class);
    private static final int ITERATIONS = 27500;
    protected final KeycloakSession session;
    protected final TokenCodeType tokenCodeType;

    ChangePasswordResource(KeycloakSession session, TokenCodeType tokenCodeType) {
        this.session = session;
        this.tokenCodeType = tokenCodeType;
    }

    private PhoneVerificationCodeProvider getTokenCodeService(KeycloakSession session) {
        return session.getProvider(PhoneVerificationCodeProvider.class);
    }

    @POST
    @NoCache
    @Path("")
    @Produces(APPLICATION_JSON)
    public Response changePassword(@NotBlank PhoneUserRepresentation representation) {
        String phoneNumber = representation.getPhoneNumber();
        String verificationCode = representation.getCode();
        if (StringUtil.isBlank(phoneNumber)) throw new BadRequestException(SupportPhonePages.Errors.MISSING.message());
        if (StringUtil.isBlank(verificationCode)) throw new BadRequestException(SupportPhonePages.Errors.MISSING_CODE.message());

        try {
            phoneNumber = Utils.canonicalizePhoneNumber(session, phoneNumber);
        } catch (PhoneNumberInvalidException e) {
            //verified in validate process
            throw new IllegalStateException();
        }

        TokenCodeRepresentation tokenCode = getTokenCodeService(session).ongoingProcess(phoneNumber, tokenCodeType);

        if (Validation.isBlank(verificationCode) || tokenCode == null || !tokenCode.getCode().equals(verificationCode)) {
            throw new BadRequestException(SupportPhonePages.Errors.NOT_MATCH.message());
        }
        session.setAttribute("tokenId", tokenCode.getId());

        try {
            UserModel user = Utils.findUserByPhone(session, session.getContext().getRealm(), phoneNumber)
              .orElseThrow(() -> new NotFoundException("User not found"));

            String tokenId = session.getAttribute("tokenId", String.class);
            getTokenCodeService(session).tokenValidated(user, phoneNumber, tokenId,false);

            // save password
            user.credentialManager().getStoredCredentialsStream()
              .forEach(cred -> {
                  if (cred.getType().equals("password")) {
                      CredentialInput input = UserCredentialModel.password(representation.getPassword(), false);
                      user.credentialManager().updateCredential(input);
                  }
              });
        } catch (Exception e) {
            logger.error("changePassword error", e);
        }

        return Response.noContent().build();
    }

    private static Optional<CredentialModel> getOtpCredentialModel(@NotNull UserModel user){
        return user.credentialManager()
          .getStoredCredentialsByTypeStream(PhoneOtpCredentialModel.TYPE).findFirst();
    }
}
