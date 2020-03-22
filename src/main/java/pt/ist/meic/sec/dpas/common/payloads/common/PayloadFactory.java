package pt.ist.meic.sec.dpas.common.payloads.common;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.StatusMessage;
import pt.ist.meic.sec.dpas.common.model.Announcement;
import pt.ist.meic.sec.dpas.common.payloads.reply.ACKPayload;
import pt.ist.meic.sec.dpas.common.payloads.reply.AnnouncementsPayload;
import pt.ist.meic.sec.dpas.common.payloads.requests.PostPayload;
import pt.ist.meic.sec.dpas.common.payloads.requests.ReadPayload;
import pt.ist.meic.sec.dpas.common.payloads.requests.RegisterPayload;
import pt.ist.meic.sec.dpas.common.utils.ArrayUtils;

import java.math.BigInteger;
import java.security.PublicKey;
import java.time.Instant;
import java.util.List;

public class PayloadFactory {
    private final static Logger logger = Logger.getLogger(PayloadFactory.class);

    public static DecryptedPayload genRequestPayloadFromOperation(Operation o, byte[] data, PublicKey key, Instant timestamp,
                                                                  List<BigInteger> linked) {
        DecryptedPayload decryptedPayload =  switch (o) {
            case REGISTER -> new RegisterPayload(key, o, timestamp);
            case POST, POST_GENERAL -> new PostPayload(new String(data), key, o, timestamp, linked);
            case READ, READ_GENERAL -> {
                Pair<PublicKey, BigInteger> pair = (Pair<PublicKey, BigInteger>) ArrayUtils.bytesToObject(data);
                yield new ReadPayload(pair, key, o, timestamp);
            }
        };
        logger.info("Decrypted " + decryptedPayload);
        return decryptedPayload;
    }

    public static DecryptedPayload genReplyPayloadFromOperation(Operation o, PublicKey key, Instant timestamp,
                                                                StatusMessage status, List<Announcement> announcements) {
        DecryptedPayload decryptedPayload = switch (o) {
            case REGISTER, POST, POST_GENERAL -> new ACKPayload(key, o, timestamp, status);
            case READ, READ_GENERAL -> new AnnouncementsPayload(key, o, timestamp, status, announcements);
        };
        logger.info("Decrypted " + decryptedPayload);
        return decryptedPayload;
    }
}
