package pt.ist.meic.sec.dpas.common.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import java.security.PublicKey;

@Entity
public class UserBoard extends Board {

    @Column(columnDefinition = "VARBINARY(4096)")
    private PublicKey owner;

    public UserBoard(PublicKey owner) {
        this.owner = owner;
    }

    // needed for hibernate
    private UserBoard() {}

    public void appendAnnouncement(Announcement a) {
        if (! a.getOwnerKey().equals(this.owner)) throw new IllegalArgumentException("Attempt to insert Announcement into wrong board.");
        super.appendAnnouncement(a);
    }

    public PublicKey getOwner() {
        return owner;
    }
}
