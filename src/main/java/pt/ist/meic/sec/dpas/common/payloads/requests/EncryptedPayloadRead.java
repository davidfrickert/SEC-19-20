package pt.ist.meic.sec.dpas.common.payloads.requests;

import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.common.PayloadFactory;
import pt.ist.meic.sec.dpas.common.utils.ArrayUtils;
import pt.ist.meic.sec.dpas.common.utils.Crypto;
import pt.ist.meic.sec.dpas.common.utils.exceptions.MissingDataException;

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
    public DecryptedPayload decrypt(PrivateKey receiverKey) throws IllegalStateException, MissingDataException {
        if(ArrayUtils.anyIsNull(this.getOperation(), this.getTimestamp(), this.getSenderKey(), this.getMessage(), receiverKey))
            throw new MissingDataException("Some fields are null and that's not allowed.");
        Operation op = Operation.fromBytes(Crypto.decryptBytes(this.getOperation(), receiverKey));
        if (op.equals(Operation.READ) && boardToReadFrom == null)
            throw new MissingDataException("Read Operation must specify a board to read.");

        Instant timestamp = Instant.parse(new String(Crypto.decryptBytes(this.getTimestamp(), receiverKey)));
        byte[] data = Crypto.decryptBytes(this.getMessage(), receiverKey);

        return PayloadFactory.genRequestPayloadFromOperation(op, data, this.getSenderKey(), timestamp, null, boardToReadFrom);
    }
}
