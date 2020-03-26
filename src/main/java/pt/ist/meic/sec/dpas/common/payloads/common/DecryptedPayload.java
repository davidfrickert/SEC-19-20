package pt.ist.meic.sec.dpas.common.payloads.common;

import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.utils.ArrayUtils;
import pt.ist.meic.sec.dpas.common.utils.Crypto;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;

public abstract class DecryptedPayload {

    private final PublicKey senderKey;
    private final Operation operation;
    private final Instant timestamp;

    public DecryptedPayload(PublicKey auth, Operation op, Instant timestamp) {
        this.senderKey = auth;
        this.operation = op;
        this.timestamp = timestamp;
    }

    public abstract Object getData();

    public byte[] asBytes() {
        return ArrayUtils.merge(this.getSenderKey().getEncoded(), this.getOperation().name().getBytes(),
                timestamp.toString().getBytes());
    }

    public PublicKey getSenderKey() {
        return senderKey;
    }

    public Operation getOperation() {
        return operation;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public abstract EncryptedPayload encrypt(PublicKey receiverKey, PrivateKey senderKey);

    public boolean verifySignature(EncryptedPayload e, PublicKey senderKey) throws IllegalStateException {
        return Crypto.verify(this.asBytes(), e.getSignature(), senderKey);
    }

}
