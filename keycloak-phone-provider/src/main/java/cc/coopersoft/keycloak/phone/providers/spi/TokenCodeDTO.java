package cc.coopersoft.keycloak.phone.providers.spi;

public class TokenCodeDTO {
  private int expiresIn;
  private String code;

  public TokenCodeDTO() {
  }

  public int getExpiresIn() {
    return expiresIn;
  }

  public void setExpiresIn(int expiresIn) {
    this.expiresIn = expiresIn;
  }

  public String getCode() {
    return code;
  }

  public void setCode(String code) {
    this.code = code;
  }
}
