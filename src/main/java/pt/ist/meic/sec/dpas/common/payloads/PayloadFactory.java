package pt.ist.meic.sec.dpas.common.payloads;

import org.apache.log4j.Logger;
import org.hibernate.cfg.NotYetImplementedException;
import pt.ist.meic.sec.dpas.common.Operation;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.List;

public class PayloadFactory {
    private final static Logger logger = Logger.getLogger(PayloadFactory.class);

    public static DecryptedPayload genPayloadFromOperation(Operation o, byte[] data, PublicKey key, List<Integer> linked) {
        logger.info("Attempt to create " + o.name() + " Payload");
        switch (o)
        {
            case REGISTER:
            default:
                throw new NotYetImplementedException();
            case POST:
            case POST_GENERAL:
                return new PostPayload(new String(data), key, o, linked);
            case READ:
            case READ_GENERAL:
                return new ReadPayload(new BigInteger(data), key, o, linked);
        }
    }
}
