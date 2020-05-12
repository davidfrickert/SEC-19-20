package pt.ist.meic.sec.dpas.common.payloads.requests;

import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.StatusMessage;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;

public class PostGeneralPreparePayload extends DecryptedPayload {
    private final static Logger logger = Logger.getLogger(PostGeneralPreparePayload.class);


    public PostGeneralPreparePayload(PublicKey auth, Instant timestamp, PrivateKey signKey) {
        super(auth, Operation.POST_GENERAL_PREPARE, timestamp);
        computeSignature(signKey);
    }

    @Override
    public String getData() {
        return null;
    }
}
