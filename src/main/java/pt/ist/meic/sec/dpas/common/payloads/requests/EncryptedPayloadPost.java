package pt.ist.meic.sec.dpas.common.payloads.requests;

import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.common.PayloadFactory;
import pt.ist.meic.sec.dpas.common.utils.ArrayUtils;
import pt.ist.meic.sec.dpas.common.utils.Crypto;
import pt.ist.meic.sec.dpas.common.utils.exceptions.MissingDataException;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.List;

public class EncryptedPayloadPost extends EncryptedPayloadRequest {
    private final byte[] linkedAnnouncements;


    public EncryptedPayloadPost(PublicKey auth, byte[] operation, byte[] timestamp, byte[] signature, byte[] message, byte[] linkedAnnouncements) {
        super(auth, operation, timestamp, signature, message);
        this.linkedAnnouncements = linkedAnnouncements;
    }

    public byte[] getLinkedAnnouncements() {
        return linkedAnnouncements;
    }

    @Override
    public DecryptedPayload decrypt(PrivateKey receiverKey) throws IllegalStateException, MissingDataException {
        if(ArrayUtils.anyIsNull(this.getOperation(), this.getTimestamp(), this.getLinkedAnnouncements(), this.getMessage()))
            throw new MissingDataException("Some fields are null and that's not allowed.");
        Operation op = Operation.fromBytes(Crypto.decryptBytes(this.getOperation(), receiverKey));
        Instant timestamp = Instant.parse(new String(Crypto.decryptBytes(this.getTimestamp(), receiverKey)));
        List<BigInteger> linked = ArrayUtils.bytesToList(Crypto.decryptBytes(this.linkedAnnouncements, receiverKey));
        byte[] data = Crypto.decryptBytes(this.getMessage(), receiverKey);

        return PayloadFactory.genRequestPayloadFromOperation(op, data, this.getSenderKey(), timestamp,
                linked, null);
    }
}
