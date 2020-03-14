package pt.ist.meic.sec.dpas.common.payloads.common;

import org.apache.log4j.Logger;
import org.hibernate.cfg.NotYetImplementedException;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.StatusMessage;
import pt.ist.meic.sec.dpas.common.payloads.reply.ACKPayload;
import pt.ist.meic.sec.dpas.common.payloads.requests.PostPayload;
import pt.ist.meic.sec.dpas.common.payloads.requests.ReadPayload;
import pt.ist.meic.sec.dpas.common.payloads.requests.RegisterPayload;

import java.math.BigInteger;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;

public class PayloadFactory {
    private final static Logger logger = Logger.getLogger(PayloadFactory.class);

    public static DecryptedPayload genRequestPayloadFromOperation(Operation o, byte[] data, PublicKey key, Instant timestamp,
                                                                  List<Integer> linked) {
        logger.info("Attempt to create " + o.name() + " RequestPayload");
        switch (o) {
            case REGISTER:
                return new RegisterPayload(key, o, timestamp);
            case POST:
            case POST_GENERAL:
                return new PostPayload(new String(data), key, o, timestamp, linked);
            case READ:
            case READ_GENERAL:
                return new ReadPayload(new BigInteger(data), key, o, timestamp);
            default:
                throw new IllegalStateException(o + " not expected, only " + Arrays.asList(Operation.REGISTER,
                        Operation.POST, Operation.POST_GENERAL, Operation.READ, Operation.READ_GENERAL) + " allowed.");
        }
    }

    public static DecryptedPayload genReplyPayloadFromOperation(Operation o, PublicKey key, Instant timestamp,
                                                                StatusMessage status, List<String> announcements) {
        logger.info("Attempt to create " + o.name() + " ReplyPayload");
        switch (o) {
            case REGISTER:
            case POST:
            case POST_GENERAL:
                return new ACKPayload(key, o, timestamp, status);

            case READ:
            case READ_GENERAL:
            default:
                throw new NotYetImplementedException();

        }
    }
}
