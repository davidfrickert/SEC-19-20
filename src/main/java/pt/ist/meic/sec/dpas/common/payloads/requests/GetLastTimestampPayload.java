package pt.ist.meic.sec.dpas.common.payloads.requests;

import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;

public class GetLastTimestampPayload extends DecryptedPayload {
    public GetLastTimestampPayload(PublicKey auth, Instant timestamp, PrivateKey signKey) {
        super(auth, Operation.GET_LAST_TIMESTAMP, timestamp);
        computeSignature(signKey);
    }

    @Override
    public Object getData() {
        return null;
    }
}
