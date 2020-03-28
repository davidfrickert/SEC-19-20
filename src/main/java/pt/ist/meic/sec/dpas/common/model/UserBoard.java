package pt.ist.meic.sec.dpas.common.model;

import pt.ist.meic.sec.dpas.common.payloads.requests.ReadPayload;

import javax.persistence.Column;
import javax.persistence.Entity;
import java.security.PublicKey;
import java.util.List;
import java.util.stream.Collectors;

@Entity
public class UserBoard extends Board {

    @Column(columnDefinition = "VARBINARY(4096)")
    private PublicKey owner;

    public UserBoard(PublicKey owner) {
        this.owner = owner;
    }

    // needed for hibernate
    private UserBoard() {}

    public boolean appendAnnouncement(Announcement a) {
        if (! a.getOwnerKey().equals(this.owner)) return false;
        super.appendAnnouncement(a);
        return true;
    }

    public PublicKey getOwner() {
        return owner;
    }

    public List<Announcement> getNAnnouncements(ReadPayload r) {
        PublicKey senderKey = r.getSenderKey();
        PublicKey boardKey = r.getBoardToReadFrom();
        if (senderKey.equals(boardKey)) {
            return super.getNAnnouncements(r);
        } else {
            throw new IllegalArgumentException("User attempted to read wrong board");
        }
    }

    @Override
    public String toString() {
        return "UserBoard{" +
                "owner=" + owner.hashCode() +
                ", announcements=" + getAnnouncements().stream().map(Announcement::asString).collect(Collectors.toList()) +
                '}';
    }
}
