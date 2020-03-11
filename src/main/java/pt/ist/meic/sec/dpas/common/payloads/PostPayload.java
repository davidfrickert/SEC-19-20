package pt.ist.meic.sec.dpas.common.payloads;

import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.utils.ArrayUtils;
import pt.ist.meic.sec.dpas.common.Operation;

import java.security.PublicKey;
import java.util.List;

public class PostPayload extends DecryptedPayload {
    private final static Logger logger = Logger.getLogger(PostPayload.class);

    private String announcement;

    public PostPayload(String announcement, PublicKey auth, Operation op, List<Integer> links) {
        super(auth, op, links);
        this.announcement = announcement;
    }

    public byte[] asBytes() {
        return ArrayUtils.merge(announcement.getBytes(), this.getSenderKey().getEncoded(),
                this.getOperation().name().getBytes(), ArrayUtils.listToBytes(this.getLinkedAnnouncements()));
    }

    public String getData() {
        return announcement;
    }
}
