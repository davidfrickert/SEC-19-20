package pt.ist.meic.sec.dpas.common.payloads.requests;

import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.common.EncryptedPayload;
import pt.ist.meic.sec.dpas.common.utils.Crypto;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;

public class RegisterPayload extends DecryptedPayload {
    private final static Logger logger = Logger.getLogger(RegisterPayload.class);

    public RegisterPayload(PublicKey auth, Operation op, Instant timestamp) {
        super(auth, op,  timestamp);
    }

    // no data yet
    @Override
    public Object getData() {
        return null;
    }

    @Override
    public EncryptedPayload encrypt(PublicKey receiverKey, PrivateKey senderKey) {
        PublicKey idKey = this.getSenderKey();
        byte[] encryptedOperation = Crypto.encryptBytes(this.getOperation().name().getBytes(), receiverKey);
        byte[] encryptedTimestamp = Crypto.encryptBytes(this.getTimestamp().toString().getBytes(), receiverKey);

        byte[] originalData = this.asBytes();

        byte[] signature = Crypto.sign(originalData, senderKey);

        return new EncryptedPayloadRequest(idKey, encryptedOperation, encryptedTimestamp, signature, null,
                null);
    }

    @Override
    public String toString() {
        return "RegisterPayload{" +
                "data=" + getData() +
                ", senderKey=" + getSenderKey().hashCode() +
                ", operation=" + getOperation() +
                ", timestamp=" + getTimestamp() +
                '}';
    }
}
