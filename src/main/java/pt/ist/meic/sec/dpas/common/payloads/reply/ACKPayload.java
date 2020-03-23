package pt.ist.meic.sec.dpas.common.payloads.reply;

import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.StatusMessage;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;
import pt.ist.meic.sec.dpas.common.utils.ArrayUtils;
import pt.ist.meic.sec.dpas.common.utils.Crypto;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;


/**
 * Payload sent as a reply to POST / POST_GENERAL / REGISTER operations
 * Represents a simple acknowledgement of success or insuccess of the operation to the client
 */
public class ACKPayload extends DecryptedPayload {
    private final static Logger logger = Logger.getLogger(ACKPayload.class);

    private final StatusMessage status;

    public ACKPayload(PublicKey auth, Operation op, Instant timestamp, StatusMessage status) {
        super(auth, op, timestamp);
        this.status = status;
    }

    @Override
    public Object getData() {
        return null;
    }

    @Override
    public byte[] asBytes() {
        return ArrayUtils.merge(super.asBytes(), this.status.asBytes());
    }

    public StatusMessage getStatus() {
        return status;
    }

    @Override
    public EncryptedPayloadReply encrypt(PublicKey receiverKey, PrivateKey senderKey) {
        PublicKey idKey = this.getSenderKey();
        byte[] encryptedOperation = Crypto.encryptBytes(this.getOperation().name().getBytes(), receiverKey);
        byte[] encryptedTimestamp = Crypto.encryptBytes(this.getTimestamp().toString().getBytes(), receiverKey);
        byte[] encryptedStatusMsg = Crypto.encryptBytes(this.status.asBytes(), receiverKey);

        byte[] originalData = this.asBytes();

        byte[] signature = Crypto.sign(originalData, senderKey);



        return new EncryptedPayloadReply(idKey, encryptedOperation,encryptedTimestamp, signature, encryptedStatusMsg);
    }

    @Override
    public String toString() {
        return "ACKPayload{" +
                "status=" + status +
                ", senderKey=" + getSenderKey().hashCode() +
                ", operation=" + getOperation() +
                ", timestamp=" + getTimestamp() +
                '}';
    }
}
