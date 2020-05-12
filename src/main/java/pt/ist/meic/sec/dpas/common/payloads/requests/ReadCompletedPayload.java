package pt.ist.meic.sec.dpas.common.payloads.requests;

import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;

public class ReadCompletedPayload extends DecryptedPayload implements Serializable {

    private PublicKey boardReadFrom;

    public ReadCompletedPayload(PublicKey senderKey,
                            Instant timestamp, PrivateKey signKey, PublicKey boardReadFrom) {
        super(senderKey, Operation.READ_COMPLETED, timestamp);
        computeSignature(signKey);
        this.boardReadFrom = boardReadFrom;
    }

    @Override
    public Object getData() {
        return null;
    }

    public PublicKey getBoardReadFrom() {
        return boardReadFrom;
    }
}
