package pt.ist.meic.sec.dpas.common.payloads.reply;

import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.StatusMessage;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.common.EncryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.common.PayloadFactory;
import pt.ist.meic.sec.dpas.common.utils.Crypto;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;

public class EncryptedPayloadReply extends EncryptedPayload {
    private final static Logger logger = Logger.getLogger(EncryptedPayloadReply.class);

    private final byte[] statusMessage;

    public EncryptedPayloadReply(PublicKey auth, byte[] operation, byte[] timestamp, byte[] signature,
                                 byte[] statusMessage) {
        super(auth, operation, timestamp, signature);
        this.statusMessage = statusMessage;
    }

    public byte[] getStatusMessage() {
        return statusMessage;
    }

    @Override
    public DecryptedPayload decrypt(PrivateKey receiverKey) {
        Operation op = Operation.fromBytes(Crypto.decryptBytes(this.getOperation(), receiverKey));
        Instant timestamp = Instant.parse(new String(Crypto.decryptBytes(this.getTimestamp(), receiverKey)));
        StatusMessage status = StatusMessage.fromBytes(Crypto.decryptBytes(this.statusMessage, receiverKey));

        DecryptedPayload dp = PayloadFactory.genReplyPayloadFromOperation(op, this.getSenderKey(), timestamp, status, null);

        return dp;
    }
}
