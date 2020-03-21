package pt.ist.meic.sec.dpas.common.model;

import pt.ist.meic.sec.dpas.common.utils.dao.DAO;

import javax.persistence.*;
import javax.transaction.Transactional;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Entity
public abstract class Board {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Transient
    private DAO<Board, Long> dao = new DAO<>(Board.class);

    @MapKey(name = "id")
    @OneToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    @JoinTable(
            name = "board_announcements",
            joinColumns = @JoinColumn(name = "board_id"),
            inverseJoinColumns = @JoinColumn(name = "announcement_id")
    )
    private Map<BigInteger, Announcement> announcements = new HashMap<>();

    public Board() { }

    public Board(Long id, Map<BigInteger, Announcement> announcements) {
        this.id = id;
        this.announcements = announcements;
    }

    @Transactional
    public void appendAnnouncement(Announcement a) {
        this.announcements.put(a.getId(), a);
        dao.update(this);
    }

    public Optional<Announcement> getById(BigInteger Id) {
        return Optional.ofNullable(announcements.get(Id));
    }
}
