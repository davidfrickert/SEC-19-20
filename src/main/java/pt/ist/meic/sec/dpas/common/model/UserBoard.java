package pt.ist.meic.sec.dpas.common.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import java.security.PublicKey;

@Entity
public class UserBoard extends Board {

    @Column(columnDefinition = "VARBINARY(4096)")
    private final PublicKey owner;

    public UserBoard(PublicKey owner) {
        this.owner = owner;
    }

    public void appendAnnouncement(Announcement a) {
        if (a.getKey() != this.owner) throw new IllegalArgumentException("Attempt to insert Announcement into wrong board.");
        this.appendAnnouncement(a);
    }

    public PublicKey getOwner() {
        return owner;
    }
}
