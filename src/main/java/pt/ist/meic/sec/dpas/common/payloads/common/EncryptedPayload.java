package pt.ist.meic.sec.dpas.common.payloads.common;

import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.utils.exceptions.MissingDataException;

import javax.persistence.Entity;
import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;

@Entity
public abstract class EncryptedPayload implements Serializable {
    private final static Logger logger = Logger.getLogger(EncryptedPayload.class);

    private final PublicKey senderKey;
    private final byte[] operation;
    private final byte[] timestamp;

    private final byte[] signature;

    public EncryptedPayload(PublicKey auth, byte[] op, byte[] timestamp, byte[] signature) {
        this.senderKey = auth;
        this.operation = op;
        this.timestamp = timestamp;
        this.signature = signature;
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

    public byte[] getTimestamp() {
        return timestamp;
    }

    public abstract DecryptedPayload decrypt(PrivateKey receiverKey) throws IllegalStateException, MissingDataException;
}
