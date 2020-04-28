package pt.ist.meic.sec.dpas.common.payloads.common;

import org.apache.log4j.Logger;

public class PayloadFactory {
    private final static Logger logger = Logger.getLogger(PayloadFactory.class);
    /*
    public static DecryptedPayload genRequestPayloadFromOperation(Operation o, byte[] data, PublicKey key, Instant timestamp,
                                                                  LinkedHashSet<BigInteger> linked, PublicKey boardToReadFrom) {
        DecryptedPayload decryptedPayload =  switch (o) {
            case REGISTER -> new RegisterPayload(new String(data) ,key, o, timestamp);
            case POST, POST_GENERAL -> new PostPayload(new String(data), key, o, timestamp, linked);
            case READ, READ_GENERAL -> new ReadPayload((BigInteger)ArrayUtils.bytesToObject(data), key, boardToReadFrom, o, timestamp);
        };
        logger.info("Decrypted " + decryptedPayload);
        return decryptedPayload;
    }

    public static DecryptedPayload genReplyPayloadFromOperation(Operation o, PublicKey key, Instant timestamp,
                                                                StatusMessage status, List<Announcement> announcements) {
        DecryptedPayload decryptedPayload;
        if (status.getStatus().equals(Status.Success)) {
            decryptedPayload = switch (o) {
                case REGISTER, POST, POST_GENERAL -> new ACKPayload(key, o, timestamp, status);
                case READ, READ_GENERAL -> new AnnouncementsPayload(key, o, timestamp, status, announcements);
            };
        } else {
            decryptedPayload = new ACKPayload(key, o, timestamp, status);
        }
        logger.info("Decrypted " + decryptedPayload);
        return decryptedPayload;
    }

     */
}
