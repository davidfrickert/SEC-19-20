package pt.ist.meic.sec.dpas.common.utils;

import org.apache.log4j.Logger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class KeyManager {

    private final static Logger logger = Logger.getLogger(KeyManager.class);

    /**
     * Loads private key file
     *
     * @param path - path of server private key
     * @return PrivateKey
     */

    public static PrivateKey loadPrivateKey(String path)  {
        try {
            byte[] keyBytes = Files.readAllBytes(Paths.get(path));
            PKCS8EncodedKeySpec spec =
                    new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            logger.info("Private key loaded from file '" + path + "'");
            return kf.generatePrivate(spec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            logger.info("Failed to load private key from file '" + path + "'. " + e.getClass().getSimpleName() + " - " + e.getMessage());
            throw new IllegalStateException();
        }
    }

    /**
     * Loads public key file
     *
     * @param path - path of server public key
     * @return PublicKey
     */

    public static PublicKey loadPublicKey(String path) {
        try {
            X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(Files.readAllBytes(Paths.get(path)));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            logger.info("Public key loaded from file '" + path + "'");
            return keyFactory.generatePublic(publicSpec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            logger.info("Failed to load public key from file '" + path + "'. " + e.getClass().getSimpleName() + " - " + e.getMessage());
            throw new IllegalStateException();
        }
    }
}
