package pt.ist.meic.sec.dpas.common.payloads;

import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.utils.ArrayUtils;
import pt.ist.meic.sec.dpas.common.utils.Crypto;
import pt.ist.meic.sec.dpas.common.Operation;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;


public class EncryptedPayload implements Serializable {
    private final static Logger logger = Logger.getLogger(EncryptedPayload.class);

    private final byte[] message;
    public PublicKey senderKey;
    private final byte[] operation;
    private final byte[] linkedAnnouncements;
    private final byte[] signature;

    public EncryptedPayload(byte[] data, PublicKey auth, byte[] op, byte[] linked, byte[] signature) {
        this.message = data;
        this.senderKey = auth;
        this.operation = op;
        this.linkedAnnouncements = linked;
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

        byte[] data = Crypto.decryptBytes(this.message, receiverKey);
        Operation op = Operation.fromBytes(Crypto.decryptBytes(this.operation, receiverKey));
        List<Integer> linked = (ArrayUtils.bytesToList(Crypto.decryptBytes(this.linkedAnnouncements, receiverKey)));

        DecryptedPayload dp = PayloadFactory.genPayloadFromOperation(op, data, this.senderKey, linked);

        Crypto.verifyDigest(dp.asBytes(), signature, senderKey);

        return dp;
    }
}
