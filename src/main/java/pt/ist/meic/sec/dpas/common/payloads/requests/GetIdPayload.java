package pt.ist.meic.sec.dpas.common.payloads.requests;

import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.AnnouncementsPayload;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;

public class GetIdPayload extends DecryptedPayload implements Serializable {

    public GetIdPayload(PublicKey senderKey,
                            Instant timestamp, PrivateKey signKey) {
        super(senderKey, Operation.GET_ID, timestamp);
        computeSignature(signKey);
    }

    @Override
    public Object getData() {
        return null;
    }
}
