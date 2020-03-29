package pt.ist.meic.sec.dpas.common.model;

import pt.ist.meic.sec.dpas.common.payloads.requests.ReadPayload;
import pt.ist.meic.sec.dpas.common.utils.dao.DAO;

import javax.persistence.*;
import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;

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

    public boolean appendAnnouncement(Announcement a) {
        this.announcements.put(a.getId(), a);
        dao.update(this);
        return true;
    }

    public List<Announcement> getNAnnouncements(ReadPayload r) {
        int n = r.getData().intValue();
        List<Announcement> allAnnouncements = getAnnouncements();
        System.out.println("Retrieving...");
        System.out.println(allAnnouncements.stream().map(Announcement::asString).collect(Collectors.toList()));
        if (n == 0) return allAnnouncements;
        System.out.println("Retrieving " + n);
        if (n > allAnnouncements.size()) return allAnnouncements;
        return new ArrayList<>(allAnnouncements.subList(allAnnouncements.size() - n, allAnnouncements.size()));
    }

    public Optional<Announcement> getById(BigInteger Id) {
        return Optional.ofNullable(announcements.get(Id));
    }

    public List<Announcement> getAnnouncements() {
        return new ArrayList<>(announcements.values());
    }

    @Override
    public String toString() {
        return "Board{" +
                "announcements=" + getAnnouncements() +
                '}';
    }
}
