package pt.ist.meic.sec.dpas.common.utils;

import org.apache.log4j.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class KeyManager {

    private final static Logger logger = Logger.getLogger(KeyManager.class);

    /**
     * Loads all public keys in scope
     * @return list of public keys
     */

    public static List<PublicKey> loadPublicKeys() {

        try (Stream<Path> walk = Files.walk(Paths.get("keys/public/clients"))) {
            List<String> result = walk.filter(Files::isRegularFile).map(Path::toString).collect(Collectors.toList());
            return result.stream().map(KeyManager::loadPublicKey).collect(Collectors.toList());
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new ArrayList<>();
    }

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
            logger.debug(new File(".").getAbsolutePath());
            throw new IllegalStateException();
        }
    }

    public static KeyStore loadKeyStore(String path, String password) {
        try {
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(new FileInputStream(path), password.toCharArray());
            return store;
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
            throw new IllegalStateException();
        }
    }
}
