package pt.ist.meic.sec.dpas.common.payloads;

import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.utils.ArrayUtils;
import pt.ist.meic.sec.dpas.common.utils.Crypto;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.List;


public class EncryptedPayload implements Serializable {
    private final static Logger logger = Logger.getLogger(EncryptedPayload.class);

    private final byte[] message;
    public PublicKey senderKey;
    private final byte[] operation;
    private final byte[] linkedAnnouncements;
    private final byte[] timestamp;

    private final byte[] signature;

    public EncryptedPayload(byte[] data, PublicKey auth, byte[] op, byte[] linked, byte[] timestamp, byte[] signature) {
        this.message = data;
        this.senderKey = auth;
        this.operation = op;
        this.linkedAnnouncements = linked;
        this.timestamp = timestamp;
        this.signature = signature;
    }

    public byte[] getMessage() {
        return message;
    }

    public byte[] getSignature() {
        return signature;
    }

    public PublicKey getSenderKey() {
        return senderKey;
    }

    public byte[] getOperation() {
        return operation;
    }

    public DecryptedPayload decrypt(PrivateKey receiverKey, PublicKey senderKey) {

        Operation op = Operation.fromBytes(Crypto.decryptBytes(this.operation, receiverKey));
        Instant timestamp = Instant.parse(new String(Crypto.decryptBytes(this.timestamp, receiverKey)));

        // linked announcements is not a general parameter (only for POST/POST_GENERAL)
        // so, it's null in other operations
        List<Integer> linked = null;
        if (this.linkedAnnouncements != null)
            linked = (ArrayUtils.bytesToList(Crypto.decryptBytes(this.linkedAnnouncements, receiverKey)));

        // data is not used yet on REGISTER, so, it might be null
        byte[] data = null;
        if (this.message != null)
            data = Crypto.decryptBytes(this.message, receiverKey);


        DecryptedPayload dp = PayloadFactory.genPayloadFromOperation(op, data, this.senderKey, timestamp, linked);

        Crypto.verifyDigest(dp.asBytes(), signature, senderKey);

        return dp;

    }
}
