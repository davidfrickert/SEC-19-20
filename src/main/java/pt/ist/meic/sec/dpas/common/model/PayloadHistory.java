package pt.ist.meic.sec.dpas.common.model;

import javax.persistence.*;
import java.io.Serializable;
import java.time.Instant;

@Entity
public class PayloadHistory implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Instant timestamp;
    @Column(columnDefinition = "VARBINARY(512)", unique = true)
    private byte[] signature;

    public PayloadHistory(Instant timestamp, byte[] signature) {
        this.timestamp = timestamp;
        this.signature = signature;
    }
}
