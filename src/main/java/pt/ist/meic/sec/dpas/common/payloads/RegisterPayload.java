package pt.ist.meic.sec.dpas.common.payloads;

import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.utils.Crypto;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;

public class RegisterPayload extends DecryptedPayload {
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
        byte[] encryptedOperation = Crypto.encryptBytes(this.getOperation().name().getBytes(), receiverKey, false);
        byte[] encryptedTimestamp = Crypto.encryptBytes(this.getTimestamp().toString().getBytes(), receiverKey, false);

        byte[] originalData = this.asBytes();

        byte[] signature = Crypto.sign(originalData, senderKey);

        return new EncryptedPayload(null, idKey, encryptedOperation, null,
                encryptedTimestamp, signature);
    }
}
