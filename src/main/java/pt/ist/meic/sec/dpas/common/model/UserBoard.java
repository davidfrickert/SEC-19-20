package pt.ist.meic.sec.dpas.common.model;

import pt.ist.meic.sec.dpas.common.utils.dao.DAO;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Transient;
import java.security.PublicKey;
import java.util.Arrays;

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
        if (! a.getKey().equals(this.owner)) throw new IllegalArgumentException("Attempt to insert Announcement into wrong board.");
        super.appendAnnouncement(a);
    }

    public PublicKey getOwner() {
        return owner;
    }
}
