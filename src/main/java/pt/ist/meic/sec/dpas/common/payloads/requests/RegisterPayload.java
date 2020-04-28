package pt.ist.meic.sec.dpas.common.payloads.requests;

import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;
import pt.ist.meic.sec.dpas.common.utils.ArrayUtils;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;

public class RegisterPayload extends DecryptedPayload {

    private String username;

    private final static Logger logger = Logger.getLogger(RegisterPayload.class);

    public RegisterPayload(String username, PublicKey auth, Operation op, Instant timestamp, PrivateKey signKey) {
        super(auth, op,  timestamp);
        this.username = username;
        computeSignature(signKey);
    }

    public byte[] asBytes() {
        return ArrayUtils.merge(username.getBytes(), super.asBytes());
    }

    @Override
    public String getData() {
        return username;
    }

    @Override
    public String toString() {
        return "RegisterPayload{" +
                "data=" + getData() +
                ", senderKey=" + getSenderKey().hashCode() +
                ", operation=" + getOperation() +
                ", timestamp=" + getTimestamp() +
                '}';
    }
}
