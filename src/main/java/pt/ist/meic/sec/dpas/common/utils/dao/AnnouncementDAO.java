package pt.ist.meic.sec.dpas.common.utils.dao;

import org.hibernate.Session;
import pt.ist.meic.sec.dpas.common.model.Announcement;

import javax.persistence.NoResultException;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Predicate;
import javax.persistence.criteria.Root;
import java.math.BigInteger;

public class AnnouncementDAO extends DAO<Announcement, BigInteger> {
    public AnnouncementDAO() {
        super(Announcement.class);
    }

    public Announcement findByHash(String hash) {
        openSessionWithTransaction();
        Session session = getCurrentSession();
        CriteriaBuilder cb = session.getCriteriaBuilder();
        CriteriaQuery<Announcement> query = cb.createQuery(getType());
        Root<Announcement> root = query.from(getType());
        Predicate nameMatches = cb.equal(root.get("hash"), hash);
        query.select(root).where(nameMatches);
        try {
            Announcement a = session.createQuery(query).getSingleResult();
            commitAndClose();
            return a;
        } catch (NoResultException e) {
            rollbackAndClose();
            return null;
        }
    }

    public boolean safeInsert(Announcement a) {
        if (findByHash(a.getHash()) != null) return false;
        this.persist(a);
        return true;
    }
}
