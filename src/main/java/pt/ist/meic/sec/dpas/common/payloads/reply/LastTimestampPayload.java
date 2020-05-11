package pt.ist.meic.sec.dpas.common.payloads.reply;

import org.apache.commons.lang3.SerializationUtils;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.StatusMessage;
import pt.ist.meic.sec.dpas.common.utils.ArrayUtils;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;

public class LastTimestampPayload extends ACKPayload {
    public LastTimestampPayload(PublicKey auth, Instant timestamp, StatusMessage status, int ts, PrivateKey signKey) {
        super(auth, Operation.GET_LAST_TIMESTAMP, timestamp, status);
        this.timestamp = ts;
        computeSignature(signKey);
    }

    private final int timestamp;

    public int getTS() {
        return timestamp;
    }

    @Override
    public byte[] asBytes() {
        return ArrayUtils.merge(SerializationUtils.serialize(BigInteger.valueOf(getTS())), super.asBytes());
    }

}
