package pt.ist.meic.sec.dpas.common.payloads;

import pt.ist.meic.sec.dpas.common.Operation;

import java.security.PublicKey;
import java.time.Instant;

public class RegisterPayload extends DecryptedPayload {
    public RegisterPayload(PublicKey auth, Operation op, Instant timestamp) {
        super(auth, op,  timestamp);
    }

    @Override
    public Object getData() {
        return null;
    }
}
