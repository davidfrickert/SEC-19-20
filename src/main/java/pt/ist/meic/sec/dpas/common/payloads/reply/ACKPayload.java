package pt.ist.meic.sec.dpas.common.payloads.reply;

import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.StatusMessage;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;
import pt.ist.meic.sec.dpas.common.utils.ArrayUtils;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;


/**
 * Payload sent as a reply to POST / POST_GENERAL / REGISTER operations
 * Represents a simple acknowledgement of success or insuccess of the operation to the client
 */
public class ACKPayload extends DecryptedPayload {
    private final static Logger logger = Logger.getLogger(ACKPayload.class);

    private StatusMessage status;

    public ACKPayload(PublicKey auth, Operation op, Instant timestamp, StatusMessage status) {
        super(auth, op, timestamp);
        this.status = status;
    }

    public ACKPayload(PublicKey auth, Operation op, Instant timestamp, StatusMessage status, PrivateKey signKey) {
        this(auth, op, timestamp, status);
        computeSignature(signKey);
    }

    @Override
    public Object getData() {
        return null;
    }

    @Override
    public byte[] asBytes() {
        byte[] status = getStatus() != null ? getStatus().asBytes() : new byte[0];
        return ArrayUtils.merge(status, super.asBytes());
    }

    public StatusMessage getStatus() {
        return status;
    }

    public void setStatus(StatusMessage status) {
        this.status = status;
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
