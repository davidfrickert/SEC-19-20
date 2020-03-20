package pt.ist.meic.sec.dpas.common.model;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Entity
public abstract class Board {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToMany
    @JoinColumn(name = "board_announcements")
    private List<Announcement> announcements = new ArrayList<>();

    public void appendAnnouncement(Announcement a) {
        this.announcements.add(a);
    }
}
