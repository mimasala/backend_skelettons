package nft.traderplace.core.security.auth.key;

import com.google.common.io.Resources;

import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class KeyReader {


    public static Key readKey(String keyPath) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] keyBytes = Resources.toByteArray(Resources.getResource(keyPath));
        try {
            return keyFactory.generatePublic(new java.security.spec.X509EncodedKeySpec(keyBytes));
        } catch (Exception e) {
            return keyFactory.generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(keyBytes));
        }
    }
}