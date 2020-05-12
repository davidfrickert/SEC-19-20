package pt.ist.meic.sec.dpas.common.payloads.requests;

import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.StatusMessage;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;

public class CommitPostPayload extends DecryptedPayload {
    private final static Logger logger = Logger.getLogger(CommitPostPayload.class);

    private StatusMessage status;

    public CommitPostPayload(PublicKey auth, Operation op, Instant timestamp, StatusMessage status, PrivateKey signKey) {
        super(auth, op, timestamp);
        this.status = status;
        computeSignature(signKey);
    }

    @Override
    public String getData() {
        return null;
    }
}
