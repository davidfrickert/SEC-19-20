package pt.ist.meic.sec.dpas.common.payloads.requests;

import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;

public class WriteBackPayload extends DecryptedPayload implements Serializable {
    private DecryptedPayload readPayload;

    public WriteBackPayload(PublicKey senderKey, Operation op,
                            Instant timestamp, PrivateKey signKey, DecryptedPayload readPayload) {
        super(senderKey, op, timestamp);
        this.readPayload = readPayload;
        computeSignature(signKey);
    }

    @Override
    public Object getData() {
        return readPayload;
    }
}
