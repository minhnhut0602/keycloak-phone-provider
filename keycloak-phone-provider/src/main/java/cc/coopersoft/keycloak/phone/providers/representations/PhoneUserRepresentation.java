package cc.coopersoft.keycloak.phone.providers.representations;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.keycloak.models.utils.KeycloakModelUtils;

import java.security.SecureRandom;
import java.util.Date;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class PhoneUserRepresentation {

    private String id;
    private String phoneNumber;
    private String code;
    private String type;
    private String password;
    private String firstName;
    private String lastName;
    private Date createdAt;
    private Date expiresAt;
    private Boolean confirmed;
    private String domain;
    private String platform;
    private String langKey;

    public static PhoneUserRepresentation forPhoneNumber(String phoneNumber) {

        PhoneUserRepresentation tokenCode = new PhoneUserRepresentation();

        tokenCode.id = KeycloakModelUtils.generateId();
        tokenCode.phoneNumber = phoneNumber;
        tokenCode.code = generateTokenCode();
        tokenCode.confirmed = false;

        return tokenCode;
    }

    private static String generateTokenCode() {
        SecureRandom secureRandom = new SecureRandom();
        Integer code = secureRandom.nextInt(999_999);
        return String.format("%06d", code);
    }
}
