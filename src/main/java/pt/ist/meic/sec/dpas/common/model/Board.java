package pt.ist.meic.sec.dpas.common.model;

import pt.ist.meic.sec.dpas.common.utils.dao.DAO;

import javax.persistence.*;
import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.List;

@Entity
public abstract class Board {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Transient
    private DAO<Board, Long> dao = new DAO<>(Board.class);

    @OneToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
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

    @Transactional
    public void appendAnnouncement(Announcement a) {
        this.announcements.add(a);
        dao.update(this);
    }
}
