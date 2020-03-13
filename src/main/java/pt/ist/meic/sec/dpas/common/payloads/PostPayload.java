package pt.ist.meic.sec.dpas.common.payloads;

import org.apache.log4j.Logger;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.utils.ArrayUtils;
import pt.ist.meic.sec.dpas.common.utils.Crypto;

import java.security.PrivateKey;
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

    @Override
    public EncryptedPayload encrypt(PublicKey receiverKey, PrivateKey senderKey) {
        byte[] encryptedData = Crypto.encryptBytes(announcement.getBytes(),  receiverKey, true);
        PublicKey idKey = this.getSenderKey();
        byte[] encryptedOperation = Crypto.encryptBytes(this.getOperation().name().getBytes(), receiverKey, true);
        byte[] encryptedLinkedAnnouncements = Crypto.encryptBytes(ArrayUtils.listToBytes(linkedAnnouncements), receiverKey, true);
        byte[] encryptedTimestamp = Crypto.encryptBytes(this.getTimestamp().toString().getBytes(), receiverKey, true);

        byte[] originalData = this.asBytes();

        byte[] signature = Crypto.sign(originalData, senderKey);

        return new EncryptedPayload(encryptedData, idKey, encryptedOperation, encryptedLinkedAnnouncements,
                encryptedTimestamp, signature);
    }

    public String getData() {
        return announcement;
    }
}
