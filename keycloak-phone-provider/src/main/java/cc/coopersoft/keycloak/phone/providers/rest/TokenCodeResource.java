package cc.coopersoft.keycloak.phone.providers.rest;

import cc.coopersoft.keycloak.phone.Utils;
import cc.coopersoft.keycloak.phone.authentication.forms.SupportPhonePages;
import cc.coopersoft.keycloak.phone.credential.PhoneOtpCredentialModel;
import cc.coopersoft.keycloak.phone.credential.PhoneOtpCredentialProvider;
import cc.coopersoft.keycloak.phone.credential.PhoneOtpCredentialProviderFactory;
import cc.coopersoft.keycloak.phone.providers.constants.TokenCodeType;
import cc.coopersoft.keycloak.phone.providers.exception.PhoneNumberInvalidException;
import cc.coopersoft.keycloak.phone.providers.representations.PhoneUserRepresentation;
import cc.coopersoft.keycloak.phone.providers.representations.TokenCodeRepresentation;
import cc.coopersoft.keycloak.phone.providers.spi.PhoneProvider;
import cc.coopersoft.keycloak.phone.providers.spi.PhoneVerificationCodeProvider;
import cc.coopersoft.keycloak.phone.providers.spi.TokenCodeDTO;
import jakarta.validation.constraints.NotBlank;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.Config;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.hash.AbstractPbkdf2PasswordHashProviderFactory;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.credential.hash.PasswordHashSpi;
import org.keycloak.credential.hash.Pbkdf2Sha256PasswordHashProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.services.validation.Validation;
import org.keycloak.userprofile.UserProfile;
import org.keycloak.userprofile.UserProfileContext;
import org.keycloak.userprofile.UserProfileProvider;
import org.keycloak.utils.StringUtil;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import static cc.coopersoft.keycloak.phone.authentication.forms.SupportPhonePages.FIELD_PHONE_NUMBER;
import static jakarta.ws.rs.core.MediaType.APPLICATION_JSON;
import static jakarta.ws.rs.core.MediaType.APPLICATION_JSON_TYPE;

public class TokenCodeResource {

  private static final Logger logger = Logger.getLogger(TokenCodeResource.class);
  protected final KeycloakSession session;
  protected final TokenCodeType tokenCodeType;
  private static final int ITERATIONS = 27500;

  TokenCodeResource(KeycloakSession session, TokenCodeType tokenCodeType) {
    this.session = session;
    this.tokenCodeType = tokenCodeType;
  }

  @GET
  @NoCache
  @Path("")
  @Produces(APPLICATION_JSON)
  public Response getTokenCode(@NotBlank @QueryParam("phoneNumber") String phoneNumber,
                               @QueryParam("kind") String kind) {
    logger.info("getTokenCode with phoneNumber: " + phoneNumber);
    logger.info("getTokenCode with kind: " + kind);

    if (Validation.isBlank(phoneNumber)) throw new BadRequestException("Must supply a phone number");

    if (phoneNumber.contains("%2B")) { // +
      phoneNumber = URLDecoder.decode(phoneNumber, StandardCharsets.UTF_8);
      logger.info("getTokenCode with decode phoneNumber: " + phoneNumber);
    }

    var phoneProvider = session.getProvider(PhoneProvider.class);

    try {
      phoneNumber = Utils.canonicalizePhoneNumber(session,phoneNumber);
    } catch (PhoneNumberInvalidException e) {
      throw new BadRequestException("Phone number is invalid");
    } catch (Exception e) {
      throw new BadRequestException(e.getMessage());
    }

    // everybody phones authenticator send AUTH code
    if( !TokenCodeType.REGISTRATION.equals(tokenCodeType) &&
        !TokenCodeType.AUTH.equals(tokenCodeType) &&
        !TokenCodeType.VERIFY.equals(tokenCodeType) &&
        Utils.findUserByPhone(session, session.getContext().getRealm(), phoneNumber).isEmpty()) {
      throw new ForbiddenException("Phone number not found");
    }

    logger.info(String.format("Requested %s code to %s", tokenCodeType.label, phoneNumber));
    TokenCodeDTO tokenExpiresIn = phoneProvider.sendTokenCode(phoneNumber,
        session.getContext().getConnection().getRemoteAddr(), tokenCodeType, kind);

    String response = String.format("{\"expires_in\":%s,\"code\":%s}", tokenExpiresIn.getExpiresIn(), tokenExpiresIn.getCode());

    return Response.ok(response, APPLICATION_JSON_TYPE).build();
  }

  @POST
  @NoCache
  @Path("")
  @Consumes(MediaType.APPLICATION_JSON)
  public Response createUser(@NotBlank PhoneUserRepresentation representation) {
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

    TokenCodeRepresentation tokenCode = getTokenCodeService(session).ongoingProcess(phoneNumber, TokenCodeType.REGISTRATION);
    logger.info("verificationCode = " + verificationCode);
    logger.info("tokenCode = " + tokenCode);
    if (Validation.isBlank(verificationCode) || tokenCode == null || !tokenCode.getCode().equals(verificationCode)) {
      logger.info("NOT_MATCH verificationCode = " + verificationCode);
      logger.info("NOT_MATCH tokenCode = " + tokenCode);
      throw new BadRequestException(SupportPhonePages.Errors.NOT_MATCH.message());
    }
    session.setAttribute("tokenId", tokenCode.getId());

    MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
    formData.add(FIELD_PHONE_NUMBER, phoneNumber);
    formData.add(UserModel.USERNAME, phoneNumber);
    formData.add(UserModel.EMAIL, String.format("%s@%s", phoneNumber, representation.getDomain()));
    formData.add(UserModel.FIRST_NAME, representation.getFirstName());
    formData.add(UserModel.LAST_NAME, representation.getLastName());

    UserProfileProvider profileProvider = session.getProvider(UserProfileProvider.class);
    try {
      UserProfile profile = profileProvider.create(UserProfileContext.REGISTRATION, formData);
      UserModel user = profile.create();
      user.setUsername(phoneNumber);
      user.setEmailVerified(true);
      user.setEnabled(true);
      user.setSingleAttribute("registered_platform", representation.getPlatform());
      user.setSingleAttribute("accountStatus", "ACTIVE");
      user.setSingleAttribute("lang_key", representation.getLangKey());
      user.setSingleAttribute("is_approved", "true");
      user.setSingleAttribute("is_terminated", "false");

      String tokenId = session.getAttribute("tokenId", String.class);
      logger.info(String.format("registration user %s phone success, tokenId is: %s", user.getId(), tokenId));
      getTokenCodeService(session).tokenValidated(user, phoneNumber, tokenId,false);

      PhoneOtpCredentialProvider ocp = (PhoneOtpCredentialProvider) session
        .getProvider(CredentialProvider.class, PhoneOtpCredentialProviderFactory.PROVIDER_ID);
      ocp.createCredential(session.getContext().getRealm(), user, PhoneOtpCredentialModel.create(phoneNumber,tokenId,0));

      // save password
      Pbkdf2Sha256PasswordHashProviderFactory factory = new Pbkdf2Sha256PasswordHashProviderFactory();

      System.setProperty("keycloak." + PasswordHashSpi.NAME + "." + Pbkdf2Sha256PasswordHashProviderFactory.ID + "." + AbstractPbkdf2PasswordHashProviderFactory.MAX_PADDING_LENGTH_PROPERTY,
        String.valueOf(0));
      factory.init(Config.scope(PasswordHashSpi.NAME, Pbkdf2Sha256PasswordHashProviderFactory.ID));
      PasswordHashProvider pbkdf2HashProvider = factory.create(null);
      CredentialModel passwordCred = pbkdf2HashProvider.encodedCredential(representation.getPassword(), ITERATIONS);
      user.credentialManager().createStoredCredential(passwordCred);
    } catch (Exception e) {
      logger.error("Error=" + e.getMessage());
      if (e.getMessage().contains("usernameExistsMessage")) {
        throw new BadRequestException(SupportPhonePages.Errors.EXISTS.message());
      }
    }

    return Response.noContent().build();
  }

  private PhoneVerificationCodeProvider getTokenCodeService(KeycloakSession session) {
    return session.getProvider(PhoneVerificationCodeProvider.class);
  }
}
