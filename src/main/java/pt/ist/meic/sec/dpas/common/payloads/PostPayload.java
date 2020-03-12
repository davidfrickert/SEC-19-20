package pt.ist.meic.sec.dpas.common.payloads;

import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.utils.ArrayUtils;

import java.security.PublicKey;
import java.time.Instant;
import java.util.List;

public class PostPayload extends DecryptedPayload {
    private final static Logger logger = Logger.getLogger(PostPayload.class);

    private final String announcement;
    private final List<Integer> linkedAnnouncements;

    public PostPayload(String announcement, PublicKey auth, Operation op, Instant timestamp, List<Integer> links) {
        super(auth, op, timestamp);
        this.announcement = announcement;
        this.linkedAnnouncements = links;
        logger.info("Created - " + op + ", " + announcement + ", " + timestamp + ", " + links.toString() + ", " + auth.hashCode());
    }

    public byte[] asBytes() {
        return ArrayUtils.merge(announcement.getBytes(), ArrayUtils.listToBytes(linkedAnnouncements), super.asBytes());
    }

    public String getData() {
        return announcement;
    }
}
