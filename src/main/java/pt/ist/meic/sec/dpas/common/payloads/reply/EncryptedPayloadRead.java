package pt.ist.meic.sec.dpas.common.payloads.reply;

import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.StatusMessage;
import pt.ist.meic.sec.dpas.common.model.Announcement;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.common.PayloadFactory;
import pt.ist.meic.sec.dpas.common.utils.Crypto;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.List;

public class EncryptedPayloadRead extends EncryptedPayloadReply {
    private final List<Announcement> announcements;
    public EncryptedPayloadRead(PublicKey auth, byte[] operation, byte[] timestamp, byte[] signature,
                                byte[] statusMessage, List<Announcement> announcements) {
        super(auth, operation, timestamp, signature, statusMessage);
        this.announcements = announcements;
    }

    @Override
    public DecryptedPayload decrypt(PrivateKey receiverKey) {
        Operation op = Operation.fromBytes(Crypto.decryptBytes(this.getOperation(), receiverKey));
        Instant timestamp = Instant.parse(new String(Crypto.decryptBytes(this.getTimestamp(), receiverKey)));
        StatusMessage status = StatusMessage.fromBytes(Crypto.decryptBytes(this.getStatusMessage(), receiverKey));

        DecryptedPayload dp = PayloadFactory.genReplyPayloadFromOperation(op, this.getSenderKey(), timestamp, status, announcements);

        return dp;
    }
}
