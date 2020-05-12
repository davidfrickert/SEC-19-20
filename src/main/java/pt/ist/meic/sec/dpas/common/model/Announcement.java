package pt.ist.meic.sec.dpas.common.model;

import org.apache.commons.codec.binary.Hex;
import pt.ist.meic.sec.dpas.common.utils.ArrayUtils;

import javax.persistence.*;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.time.Instant;
import java.util.*;

@Entity
public class Announcement implements Serializable, Comparable<Announcement> {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(columnDefinition = "BIGINT")
    private BigInteger id;

    @Column(unique = true)
    private String hash;

    private String message;
    private final Instant receivedTime = Instant.now();
    private Instant sendTime;

    private int wtsTimestamp;

    @Column(columnDefinition = "VARBINARY(4096)")
    private PublicKey creatorId;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name="linked_announcements",
    joinColumns = @JoinColumn(name = "id", referencedColumnName = "id"))
    @Column(nullable = false, columnDefinition = "BIGINT")
    private Set<BigInteger> referred;

    public Announcement(String message, PublicKey creatorId, Set<BigInteger> referred, Instant sendTime, int wtsTimestamp) {
        this.message = message;
        this.creatorId = creatorId;
        this.referred = referred;
        this.sendTime = sendTime;
        this.wtsTimestamp = wtsTimestamp;

        this.hash = calcHash();
    }

    public Announcement(String message, PublicKey creatorId, Instant sendTime) {
        this.message = message;
        this.creatorId = creatorId;
        this.referred = new HashSet<>();
        this.sendTime = sendTime;

        this.hash = calcHash();
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

    public Instant getReceivedTime() {
        return receivedTime;
    }

    public PublicKey getCreatorId() {
        return creatorId;
    }

    public Set<BigInteger> getReferred() {
        return referred;
    }

    public String asString() {
        return "Announcement{" +
                "id=" + id +
                ", message='" + message + '\'' +
                ", creationTime=" + receivedTime +
                ", creatorId=" + creatorId.hashCode() +
                ", referred=" + referred +
                '}';
    }

    public int getWtsTimestamp() {
        return wtsTimestamp;
    }

    private String calcHash() {
        try {
            MessageDigest d = MessageDigest.getInstance("SHA-512");
            List<Object> fields = Arrays.asList(message, wtsTimestamp, creatorId, referred);
            String digest = Hex.encodeHexString(d.digest(ArrayUtils.objectToBytes(fields)));
            System.out.println("Announcement Digest: " + digest);
            return digest;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException();
        }
    }

    public String getHash() {
        return this.hash;
    }

    @Override
    public int compareTo(Announcement o) {
        if (receivedTime == null) return 0;
        return o.receivedTime.compareTo(this.receivedTime);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Announcement that = (Announcement) o;
        return hash.equals(that.hash);
    }

    @Override
    public int hashCode() {
        return Objects.hash(hash);
    }
}
