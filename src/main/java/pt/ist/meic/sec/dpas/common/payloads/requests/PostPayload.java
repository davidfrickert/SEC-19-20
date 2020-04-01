package pt.ist.meic.sec.dpas.common.payloads.requests;

import org.apache.commons.lang3.SerializationUtils;
import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.payloads.common.DecryptedPayload;
import pt.ist.meic.sec.dpas.common.payloads.common.EncryptedPayload;
import pt.ist.meic.sec.dpas.common.utils.ArrayUtils;
import pt.ist.meic.sec.dpas.common.utils.Crypto;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Set;


public class PostPayload extends DecryptedPayload {
    private final static Logger logger = Logger.getLogger(PostPayload.class);

    private final String announcement;
    private final LinkedHashSet<String> linkedAnnouncements;


    public Set<String> getLinkedAnnouncements() {
        return linkedAnnouncements;
    }


    public PostPayload(String announcement, PublicKey auth, Operation op, Instant timestamp, LinkedHashSet<String> links) {
        super(auth, op, timestamp);
        this.announcement = announcement;
        // necessary because weird handling of conversion to bytes...
        //this.linkedAnnouncements = ArrayUtils.bytesToSet(ArrayUtils.objectToBytes(links));
        this.linkedAnnouncements = links;
        //logger.info("Created - " + op + ", " + announcement + ", " + timestamp + ", " + links.toString() + ", " + auth.hashCode());
    }

    public byte[] asBytes() {
        return ArrayUtils.merge(SerializationUtils.serialize(this.linkedAnnouncements),announcement.getBytes(), super.asBytes());
    }

    @Override
    public EncryptedPayload encrypt(PublicKey receiverKey, PrivateKey senderKey) {
        byte[] encryptedData = Crypto.encryptBytes(announcement.getBytes(),  receiverKey);
        PublicKey idKey = this.getSenderKey();
        byte[] encryptedOperation = Crypto.encryptBytes(this.getOperation().name().getBytes(), receiverKey);
        byte[] encryptedLinkedAnnouncements = Crypto.encryptBytes(SerializationUtils.serialize(this.linkedAnnouncements), receiverKey);
        byte[] encryptedTimestamp = Crypto.encryptBytes(this.getTimestamp().toString().getBytes(), receiverKey);

        byte[] originalData = this.asBytes();

        byte[] signature = Crypto.sign(originalData, senderKey);

        return new EncryptedPayloadPost(idKey, encryptedOperation, encryptedTimestamp, signature, encryptedData,
                encryptedLinkedAnnouncements);
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
}
