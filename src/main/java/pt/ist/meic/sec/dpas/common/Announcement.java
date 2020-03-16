package pt.ist.meic.sec.dpas.common;

import pt.ist.meic.sec.dpas.common.utils.ArrayUtils;

import java.io.Serializable;
import java.security.PublicKey;
import java.time.Instant;
import java.util.List;

public class Announcement implements Serializable {
    private final String message;
    private final Instant creationTime;
    private final PublicKey creatorId;
    private final List<Announcement> referred;

    public Announcement(String message, PublicKey creatorId, List<Announcement> referred) {
        this.message = message;
        this.creationTime = Instant.now();
        this.creatorId = creatorId;
        this.referred = referred;
    }

    public byte[] asBytes() {
        return ArrayUtils.objectToBytes(this);
    }

    public static Announcement fromBytes(byte[] bytes) {
        return ArrayUtils.bytesToGeneric(bytes);
    }
}
