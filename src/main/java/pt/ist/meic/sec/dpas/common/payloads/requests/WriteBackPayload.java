package pt.ist.meic.sec.dpas.common.payloads.requests;

import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.AnnouncementsPayload;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;

public class WriteBackPayload extends DecryptedPayload implements Serializable {
    private AnnouncementsPayload readPayload;

    public WriteBackPayload(PublicKey senderKey,
                            Instant timestamp, PrivateKey signKey, AnnouncementsPayload readPayload) {
        super(senderKey, Operation.WRITE_BACK, timestamp);
        this.readPayload = readPayload;
        computeSignature(signKey);
    }

    @Override
    public AnnouncementsPayload getData() {
        return readPayload;
    }
}
