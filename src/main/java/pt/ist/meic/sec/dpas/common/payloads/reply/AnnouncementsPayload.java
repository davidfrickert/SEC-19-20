package pt.ist.meic.sec.dpas.common.payloads.reply;

import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.StatusMessage;
import pt.ist.meic.sec.dpas.common.model.Announcement;
import pt.ist.meic.sec.dpas.common.utils.ArrayUtils;
import pt.ist.meic.sec.dpas.common.utils.Crypto;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.List;

/**
 * Represent a Payload as a reply to READ / READ_GENERAL operations
 * Contains the announcements requested if the request was accepted
 */

public class AnnouncementsPayload extends ACKPayload {

    private final List<Announcement> announcements;

    public AnnouncementsPayload(PublicKey auth, Operation op, Instant timestamp, StatusMessage status,
                                List<Announcement> announcements) {
        super(auth, op, timestamp, status);
        this.announcements = announcements;
    }

    @Override
    public byte[] asBytes() {
        return ArrayUtils.merge(super.asBytes(), ArrayUtils.objectToBytes(this.announcements));
    }

    public List<Announcement> getAnnouncements() {
        return announcements;
    }

    @Override
    public EncryptedPayloadReply encrypt(PublicKey receiverKey, PrivateKey senderKey) {
        PublicKey idKey = this.getSenderKey();
        byte[] encryptedOperation = Crypto.encryptBytes(this.getOperation().name().getBytes(), receiverKey);
        byte[] encryptedTimestamp = Crypto.encryptBytes(this.getTimestamp().toString().getBytes(), receiverKey);
        byte[] encryptedStatusMsg = Crypto.encryptBytes(this.getStatus().asBytes(), receiverKey);
        byte[] encryptedAnnouncements = Crypto.encryptBytes(ArrayUtils.objectToBytes(this.announcements), receiverKey);

        byte[] originalData = this.asBytes();

        byte[] signature = Crypto.sign(originalData, senderKey);



        return new EncryptedPayloadReply(idKey, encryptedOperation,encryptedTimestamp, signature, encryptedStatusMsg
                , encryptedAnnouncements );
    }

    @Override
    public String toString() {
        return "AnnouncementsPayload{" +
                "announcements=" + announcements +
                ", status=" + getStatus() +
                ", senderKey=" + getSenderKey().hashCode() +
                ", operation=" + getOperation() +
                ", timestamp=" + getTimestamp() +
                '}';
    }
}
