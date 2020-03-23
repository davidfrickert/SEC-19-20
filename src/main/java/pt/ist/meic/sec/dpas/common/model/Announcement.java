package pt.ist.meic.sec.dpas.common.model;

import pt.ist.meic.sec.dpas.common.utils.ArrayUtils;

import javax.persistence.*;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Entity
public class Announcement implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(columnDefinition = "BIGINT")
    private BigInteger id;

    private String message;
    private final Instant creationTime = Instant.now();

    @Column(columnDefinition = "VARBINARY(4096)")
    private PublicKey creatorId;
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name="linked_announcements",
    joinColumns = @JoinColumn(name = "id", columnDefinition = "BIGINT"))
    @Column(columnDefinition = "BIGINT")
    private List<BigInteger> referred;

    public Announcement(String message, PublicKey creatorId, List<BigInteger> referred) {
        this.message = message;
        this.creatorId = creatorId;
        this.referred = referred;
    }

    public Announcement(String message, PublicKey creatorId) {
        this.message = message;
        this.creatorId = creatorId;
        this.referred = new ArrayList<>();
    }

    private Announcement() {}

    public byte[] asBytes() {
        return ArrayUtils.objectToBytes(this);
    }

    public static Announcement fromBytes(byte[] bytes) {
        return ArrayUtils.bytesToGeneric(bytes);
    }

    public BigInteger getId() {
        return id;
    }

    public PublicKey getOwnerKey() {
        return creatorId;
    }

    public String getMessage() {
        return message;
    }

    public Instant getCreationTime() {
        return creationTime;
    }

    public PublicKey getCreatorId() {
        return creatorId;
    }

    public List<BigInteger> getReferred() {
        return referred;
    }

    public String asString() {
        return "Announcement{" +
                "id=" + id +
                ", message='" + message + '\'' +
                ", creationTime=" + creationTime +
                ", creatorId=" + creatorId.hashCode() +
                ", referred=" + referred +
                '}';
    }
}
