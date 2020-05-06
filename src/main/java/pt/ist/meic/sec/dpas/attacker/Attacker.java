package pt.ist.meic.sec.dpas.attacker;

import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.client.ClientLibrary;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.requests.ReadPayload;
import pt.ist.meic.sec.dpas.common.utils.exceptions.IncorrectSignatureException;
import pt.ist.meic.sec.dpas.server.DPAServer;
import pt.ist.meic.sec.dpas.server.ServerLauncher;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class Attacker {
    private final static Logger logger = Logger.getLogger(Attacker.class);

    private PrivateKey privateKey;
    private PublicKey publicKey;

    private static final String KEYSTORE_PATH = "keys/private/clients/attacker.p12";
    private static final String KEY_ALIAS = "client";

    private ClientLibrary library;

    public Attacker(int serverPort) {
        try{
            FileInputStream is = new FileInputStream(KEYSTORE_PATH);

            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(is, "attacker".toCharArray());

            Key key = keystore.getKey(KEY_ALIAS, "attacker".toCharArray());
            if (key instanceof PrivateKey) {
                // Get certificate of public key
                Certificate cert = keystore.getCertificate(KEY_ALIAS);

                // Get public key
                publicKey = cert.getPublicKey();

                // Return a key pair
                KeyPair keyPair = new KeyPair(publicKey, (PrivateKey) key);
                privateKey = keyPair.getPrivate();
                publicKey = keyPair.getPublic();
            }
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException e) {
            e.printStackTrace();
            throw new IllegalStateException("Problems with keystore, client not starting.");
        }

        InetAddress host;
        try {
            host = InetAddress.getLocalHost();
            library = new ClientLibrary();
            library.start(host.getHostName(), serverPort);
        } catch (UnknownHostException e) {
            e.printStackTrace();
            throw new IllegalStateException(e);
        }
    }

    public DecryptedPayload sendInterceptedRequestPayload(DecryptedPayload intercepted, AttackType type, Operation operation) throws SocketTimeoutException, IncorrectSignatureException {
        return switch (type) {
            case MITM -> mitm(intercepted, operation);
            case REPLAY -> replay(intercepted, operation);
        };
    }

    public DecryptedPayload buildMissingInformationPayload() {
        return new ReadPayload(null, getPublicKey(), null, null, null, privateKey);
    }

    private DecryptedPayload mitm(DecryptedPayload intercepted, Operation operation) throws SocketTimeoutException, IncorrectSignatureException {
        // PublicKey auth, byte[] operation, byte[] timestamp, byte[] signature, byte[] message, byte[] linkedAnnouncements
        intercepted.setSenderKey(this.publicKey);
        // attempt with a random operation because attacker can't figure out which operation this message is because it's
        // encrypted..
        library.write(intercepted);
        DecryptedPayload response = library.receiveReply();
        return response;
    }

    private DecryptedPayload replay(DecryptedPayload intercepted, Operation operation) throws SocketTimeoutException, IncorrectSignatureException {
        // edited - this should encrypt with the attacker's key, can't have null encryption key.
        library.write(intercepted);
        DecryptedPayload response = library.receiveReply();
        return response;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
}
