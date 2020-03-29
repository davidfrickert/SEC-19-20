package pt.ist.meic.sec.dpas.attacker;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.client.ClientLibrary;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.common.EncryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.requests.EncryptedPayloadRequest;
import pt.ist.meic.sec.dpas.common.utils.KeyManager;
import pt.ist.meic.sec.dpas.server.DPAServer;

import java.io.IOException;
import java.net.InetAddress;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Attacker {
    private final static Logger logger = Logger.getLogger(Attacker.class);

    private PrivateKey privateKey;
    private PublicKey publicKey;
    private PublicKey serverKey;

    private ClientLibrary library;

    public Attacker() throws IOException {
        privateKey = KeyManager.loadPrivateKey("keys/private/clients/private8.der");
        publicKey = KeyManager.loadPublicKey("keys/public/clients/pub8.der");

        InetAddress host = InetAddress.getLocalHost();
        library = new ClientLibrary();
        library.start(host.getHostName(), DPAServer.getPort());
    }

    public DecryptedPayload sendInterceptedRequestPayload(EncryptedPayloadRequest intercepted, AttackType type, Operation operation) {
        return switch (type) {
            case MITM -> mitm(intercepted, operation);
            case REPLAY -> replay(intercepted, operation);
        };
    }

    private DecryptedPayload mitm(EncryptedPayloadRequest intercepted, Operation operation) {
        // PublicKey auth, byte[] operation, byte[] timestamp, byte[] signature, byte[] message, byte[] linkedAnnouncements
        EncryptedPayload modifiedByAttacker = new EncryptedPayloadRequest(this.publicKey, intercepted.getOperation(),
                intercepted.getTimestamp(), intercepted.getSignature(), intercepted.getMessage());
        // attempt with a random operation because attacker can't figure out which operation this message is because it's
        // encrypted..
        Pair<DecryptedPayload, EncryptedPayload> response = library.sendPayloadToServer(modifiedByAttacker, operation, privateKey);
        return response.getLeft();
    }

    private DecryptedPayload replay(EncryptedPayloadRequest intercepted, Operation operation) {
        // edited - this should encrypt with the attacker's key, can't have null encryption key.
        Pair<DecryptedPayload, EncryptedPayload> response = library.sendPayloadToServer(intercepted, operation, privateKey);
        return response.getLeft();
    }

}
