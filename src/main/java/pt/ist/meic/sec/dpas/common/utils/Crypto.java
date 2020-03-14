package pt.ist.meic.sec.dpas.common.utils;

import org.apache.log4j.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class Crypto {
    private final static Logger logger = Logger.getLogger(Crypto.class);
    private final static String digestAlgorithm = "SHA-512";

    public static byte[] decryptBytes(byte[] message, Key key) {
        try {
            //https://cryptosense.com/blog/why-pkcs1v1-5-encryption-should-be-put-out-of-our-misery/
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, key);
            //String decryptedString = new String(enc, StandardCharsets.UTF_8);
            //logger.info("Decrypted as: '" + decryptedString + "'");
            //return decryptedString;
            return rsaCipher.doFinal(message);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            throw new IllegalStateException();
        }
    }

    public static byte[] encryptBytes(byte[] message, Key key) {
        try {
            //https://cryptosense.com/blog/why-pkcs1v1-5-encryption-should-be-put-out-of-our-misery/
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] enc = rsaCipher.doFinal(message);
            /*
            if (log) {
                logger.info("Encrypted message: '" + new String(message) + "'");
            }
             */
            return enc;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            throw new IllegalStateException();
        }
    }

    public static byte[] sign(byte[] digest, PrivateKey key) {
        try {
            Signature s = Signature.getInstance("SHA512withRSA");
            s.initSign(key);
            s.update(digest);
            return s.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            throw new IllegalStateException();
        }
    }

    public static boolean verify(byte[] data, byte[] signature, PublicKey key) {
        try {
            Signature s = Signature.getInstance("SHA512withRSA");
            s.initVerify(key);
            s.update(data);
            return s.verify(signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            throw new IllegalStateException();
        }
    }



    public static List<byte[]> decryptMultiple(Key key, byte[] ...data) {
        return Arrays.stream(data).map(a -> decryptBytes(a, key)).collect(Collectors.toList());
    }

    public static List<byte[]> encryptMultiple(Key key, byte[] ...data) {
        return Arrays.stream(data).map(a -> encryptBytes(a, key)).collect(Collectors.toList());
    }




    public static PublicKey publicKeyFromBytes(byte[] bytes) {
        try {
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytes));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new IllegalStateException();
        }
    }

    public static PrivateKey privateKeyFromBytes(byte[] bytes) {
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(bytes));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new IllegalStateException();
        }
    }

    public static byte[] digest(byte[] message) {
        try {
            MessageDigest md = MessageDigest.getInstance(digestAlgorithm);
            return md.digest(message);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new IllegalStateException();
        }
    }

    /**
     * This method aims to validate that the 'data' was sent by the owner of the 'key' supplied
     * If the digest obtained with the decrypted 'data' is not the same as the one received, the data was tampered!
     *
     * @param data - decrypted data
     * @param signature  - digest received
     * @param pub - public key of sender
     */

    public static void verifyDigest(byte[] data, byte[] signature, PublicKey pub) {

        // verify signature
        boolean valid = Crypto.verify(data, signature, pub);
        // hash generated by the sender

        // if hash of the data we received doesn't match with the hash generated by sender
        // TAMPERED!!
        if (! valid) {
            logger.warn("SHA512 NOT OK.");
        } else {
            logger.info("SHA512 OK.");
        }
    }



}
