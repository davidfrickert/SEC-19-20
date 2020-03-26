package pt.ist.meic.sec.dpas.common.payloads.requests;

import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.common.PayloadFactory;
import pt.ist.meic.sec.dpas.common.utils.Crypto;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;

public class EncryptedPayloadRead extends EncryptedPayloadRequest {
    private final static Logger logger = Logger.getLogger(EncryptedPayloadRead.class);

    private PublicKey boardToReadFrom;

    public EncryptedPayloadRead(PublicKey auth, PublicKey boardToReadFrom, byte[] operation, byte[] timestamp, byte[] signature, byte[] message) {
        super(auth, operation, timestamp, signature, message);
        this.boardToReadFrom = boardToReadFrom;
    }

    public PublicKey getBoardToReadFrom() {
        return boardToReadFrom;
    }

    @Override
    public DecryptedPayload decrypt(PrivateKey receiverKey) throws IllegalStateException {

        Operation op = Operation.fromBytes(Crypto.decryptBytes(this.getOperation(), receiverKey));
        Instant timestamp = Instant.parse(new String(Crypto.decryptBytes(this.getTimestamp(), receiverKey)));
        byte[] data = Crypto.decryptBytes(this.getMessage(), receiverKey);

        return PayloadFactory.genRequestPayloadFromOperation(op, data, this.getSenderKey(), timestamp, null, boardToReadFrom);
    }
}
