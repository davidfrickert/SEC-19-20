package pt.ist.meic.sec.dpas.common.payloads.requests;

import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.common.EncryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.common.PayloadFactory;
import pt.ist.meic.sec.dpas.common.utils.ArrayUtils;
import pt.ist.meic.sec.dpas.common.utils.Crypto;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.List;

public class EncryptedPayloadRequest extends EncryptedPayload {
    private final byte[] message;

    private final byte[] linkedAnnouncements;

    public EncryptedPayloadRequest(PublicKey auth, byte[] operation, byte[] timestamp, byte[] signature,
                                   byte[] message, byte[] linkedAnnouncements) {
        super(auth, operation, timestamp, signature);
        this.message = message;
        this.linkedAnnouncements = linkedAnnouncements;
    }

    @Override
    public DecryptedPayload decrypt(PrivateKey receiverKey) {

        Operation op = Operation.fromBytes(Crypto.decryptBytes(this.getOperation(), receiverKey));
        Instant timestamp = Instant.parse(new String(Crypto.decryptBytes(this.getTimestamp(), receiverKey)));

        // linked announcements is not a general parameter (only for POST/POST_GENERAL)
        // so, it's null in other operations
        List<BigInteger> linked = null;
        if (this.linkedAnnouncements != null)
            linked = ArrayUtils.bytesToList(Crypto.decryptBytes(this.linkedAnnouncements, receiverKey));

        // data is not used yet on REGISTER, so, it might be null
        byte[] data = null;
        if (this.message != null)
            data = Crypto.decryptBytes(this.message, receiverKey);

        DecryptedPayload dp = PayloadFactory.genRequestPayloadFromOperation(op, data, this.getSenderKey(), timestamp, linked);

        return dp;
    }

    public byte[] getMessage() {
        return message;
    }

    public byte[] getLinkedAnnouncements() {
        return linkedAnnouncements;
    }
}
