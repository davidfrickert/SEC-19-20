package pt.ist.meic.sec.dpas.common.payloads;

import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.Operation;

import java.math.BigInteger;
import java.security.PublicKey;
import java.time.Instant;
import java.util.List;

public class PayloadFactory {
    private final static Logger logger = Logger.getLogger(PayloadFactory.class);

    public static DecryptedPayload genPayloadFromOperation(Operation o, byte[] data, PublicKey key, Instant timestamp,
                                                           List<Integer> linked) {
        logger.info("Attempt to create " + o.name() + " Payload");
        switch (o)
        {
            case REGISTER:
            default:
                return new RegisterPayload(key, o, timestamp);
            case POST:
            case POST_GENERAL:
                return new PostPayload(new String(data), key, o, timestamp, linked);
            case READ:
            case READ_GENERAL:
                return new ReadPayload(new BigInteger(data), key, o, timestamp);
        }
    }
}
