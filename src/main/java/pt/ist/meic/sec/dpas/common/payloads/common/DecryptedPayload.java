package pt.ist.meic.sec.dpas.common.payloads.common;

import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.utils.ArrayUtils;
import pt.ist.meic.sec.dpas.common.utils.Crypto;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;

public abstract class DecryptedPayload implements Serializable {

    private PublicKey senderKey;
    private final Operation operation;
    private final Instant timestamp;
    private byte[] signature;

    public DecryptedPayload(PublicKey auth, Operation op, Instant timestamp) {
        this.senderKey = auth;
        this.operation = op;
        this.timestamp = timestamp;
    }

    public abstract Object getData();

    public byte[] asBytes() {
        byte[] senderKey = getSenderKey() != null ? getSenderKey().getEncoded() : new byte[0];
        byte[] operation = getOperation() != null ? getOperation().name().getBytes() : new byte[0];
        byte[] timestamp = getTimestamp() != null ? getTimestamp().toString().getBytes() : new byte[0];
        return ArrayUtils.merge(senderKey, operation, timestamp);
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

    public void computeSignature(PrivateKey priv) {
        this.signature = Crypto.sign(this.asBytes(), priv);
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setSenderKey(PublicKey senderKey) {
        this.senderKey = senderKey;
    }

    public boolean verifySignature() {
        return Crypto.verify(asBytes(), getSignature(), senderKey);
    }

}
