package pt.ist.meic.sec.dpas.common.payloads.requests;

import org.apache.commons.lang3.SerializationUtils;
import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;
import pt.ist.meic.sec.dpas.common.utils.ArrayUtils;
import pt.ist.meic.sec.dpas.common.utils.Crypto;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Set;


public class PostPayload extends DecryptedPayload {
    private final static Logger logger = Logger.getLogger(PostPayload.class);

    private final String announcement;
    private final LinkedHashSet<BigInteger> linkedAnnouncements;
    private byte[] timestampAndValueSignature;


    public Set<BigInteger> getLinkedAnnouncements() {
        return linkedAnnouncements;
    }


    public PostPayload(String announcement, PublicKey auth, Operation op, Instant timestamp,
                       LinkedHashSet<BigInteger> links, PrivateKey signKey) {
        super(auth, op, timestamp);
        this.announcement = announcement;
        // temporary fix
        this.linkedAnnouncements = SerializationUtils.deserialize(SerializationUtils.serialize(links));
        computeSignature(signKey);
    }

    public byte[] asBytes() {
        return ArrayUtils.merge(SerializationUtils.serialize(this.linkedAnnouncements),announcement.getBytes(), super.asBytes());
    }

    public String getData() {
        return announcement;
    }

    @Override
    public String toString() {
        return "PostPayload{" +
                "announcement='" + announcement + '\'' +
                ", linkedAnnouncements=" + linkedAnnouncements +
                ", senderKey=" + (getSenderKey() != null ? getSenderKey().hashCode() : null) +
                ", operation=" + getOperation() +
                ", timestamp=" + getTimestamp() +
                '}';
    }

    public void computeSignature(PrivateKey priv) {
        super.computeSignature(priv);
        // timestamp, String, List of related ids
        byte[] data = ArrayUtils.merge(
                SerializationUtils.serialize(BigInteger.valueOf(getMsgId())),
                announcement.getBytes(),
                SerializationUtils.serialize(linkedAnnouncements)
        );
        timestampAndValueSignature = Crypto.sign(data, priv);
    }

}
