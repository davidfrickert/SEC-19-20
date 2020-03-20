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
    @JoinTable(
            name = "board_announcements",
            joinColumns = @JoinColumn(name = "board_id"),
            inverseJoinColumns = @JoinColumn(name = "announcement_id")
    )
    private List<Announcement> announcements = new ArrayList<>();

    public Board() {}

    public Board(Long id, List<Announcement> announcements) {
        this.id = id;
        this.announcements = announcements;
    }

    public void appendAnnouncement(Announcement a) {
        this.announcements.add(a);
    }
}
