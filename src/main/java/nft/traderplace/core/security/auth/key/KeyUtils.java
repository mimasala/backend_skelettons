package nft.traderplace.core.security.auth.key;


import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

@Component
@Log4j2
public class KeyUtils {
    @Value("${access-token.private}")
    private String accessTokenPrivateKey;
    @Value("${access-token.public}")
    private String accessTokenPublicKey;
    @Value("${refresh-token.private}")
    private String refreshTokenPrivateKey;
    @Value("${refresh-token.public}")
    private String refreshTokenPublicKey;

    private KeyPair _accessTokenKeyPair;
    private KeyPair _refreshTokenKeyPair;
    @Autowired
    Environment environment;

    public RSAPublicKey getAccessTokenPublicKey() {
        return (RSAPublicKey) Objects.requireNonNull(getAccessTokenKeyPair()).getPublic();
    }
    public RSAPrivateKey getAccessTokenPrivateKey() {
        return (RSAPrivateKey) Objects.requireNonNull(getAccessTokenKeyPair()).getPrivate();
    }
    public RSAPublicKey getRefreshTokenPublicKey() {
        return (RSAPublicKey) Objects.requireNonNull(getRefreshTokenKeyPair()).getPublic();
    }
    public RSAPrivateKey getRefreshTokenPrivateKey() {
        return (RSAPrivateKey) Objects.requireNonNull(getRefreshTokenKeyPair()).getPrivate();
    }

    private KeyPair getAccessTokenKeyPair() {
        if (Objects.isNull(_accessTokenKeyPair)) {
            _accessTokenKeyPair = getKeyPair(accessTokenPublicKey, accessTokenPrivateKey);
        }
        return _accessTokenKeyPair;
    }
    private KeyPair getRefreshTokenKeyPair() {
        if (Objects.isNull(_refreshTokenKeyPair)) {
            _refreshTokenKeyPair = getKeyPair(refreshTokenPublicKey, refreshTokenPrivateKey);
        }
        return _refreshTokenKeyPair;
    }

    private KeyPair getKeyPair(String publicKey, String privateKey){
        try {
            return new KeyPair(
                    (PublicKey) KeyReader.readKey(publicKey),
                    (PrivateKey) KeyReader.readKey(privateKey)
            );
        } catch (Exception e) {
            log.fatal(e);
            return null;
        }
    }
}
