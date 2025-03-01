package pt.ist.meic.sec.dpas.common.payloads.reply;

import org.apache.commons.lang3.SerializationUtils;
import pt.ist.meic.sec.dpas.common.Operation;
import pt.ist.meic.sec.dpas.common.StatusMessage;
import pt.ist.meic.sec.dpas.common.model.Announcement;
import pt.ist.meic.sec.dpas.common.utils.ArrayUtils;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Represent a Payload as a reply to READ / READ_GENERAL operations
 * Contains the announcements requested if the request was accepted
 */

public class AnnouncementsPayload extends ACKPayload {

    private List<Announcement> announcements;

    public AnnouncementsPayload(PublicKey auth, Operation op, Instant timestamp, StatusMessage status,
                                List<Announcement> announcements, PrivateKey signKey) {
        super(auth, op, timestamp, status);
        // temporary fix
        this.announcements = SerializationUtils.deserialize(SerializationUtils.serialize(new ArrayList<>(announcements)));
        computeSignature(signKey);
    }

    public AnnouncementsPayload(PublicKey auth, Operation op, Instant timestamp, StatusMessage status, Integer msgId,
                                List<Announcement> announcements, PrivateKey signKey) {
        super(auth, op, timestamp, status);
        // temporary fix
        this.announcements = SerializationUtils.deserialize(SerializationUtils.serialize(new ArrayList<>(announcements)));
        this.setMsgId(msgId);
        computeSignature(signKey);
    }

    @Override
    public byte[] asBytes() {
        return ArrayUtils.merge(ArrayUtils.objectToBytes(this.announcements), super.asBytes());
    }

    public List<Announcement> getAnnouncements() {
        return announcements;
    }

    public void setAnnouncements(List<Announcement> announcements) {
        this.announcements = announcements;
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AnnouncementsPayload that = (AnnouncementsPayload) o;
        return Objects.equals(announcements, that.announcements);
    }

    @Override
    public int hashCode() {
        return Objects.hash(announcements);
    }
}
