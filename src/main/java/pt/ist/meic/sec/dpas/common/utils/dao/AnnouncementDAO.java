package pt.ist.meic.sec.dpas.common.utils.dao;

import org.hibernate.Session;
import pt.ist.meic.sec.dpas.common.model.Announcement;
import pt.ist.meic.sec.dpas.common.utils.HibernateConfig;

import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Predicate;
import javax.persistence.criteria.Root;
import java.math.BigInteger;
import java.util.List;
import java.util.Set;

public class AnnouncementDAO extends DAO<Announcement, BigInteger> {
    public AnnouncementDAO(HibernateConfig config) {
        super(Announcement.class, config);
    }

    public List<Announcement> findByAttr(String attr, Object ...values) {
        openSessionWithTransaction();
        Session session = getCurrentSession();
        CriteriaBuilder cb = session.getCriteriaBuilder();
        CriteriaQuery<Announcement> query = cb.createQuery(getType());
        Root<Announcement> root = query.from(getType());
        //Predicate nameMatches = cb.equal(root.get("hash"), hash);
        Predicate nameMatches = root.get(attr).in(values);
        query.select(root).where(nameMatches);

        List<Announcement> a = session.createQuery(query).getResultList();
        commitAndClose();
        return a;

    }

    public List<Announcement> findByIds(BigInteger ...ids) {
        return findByAttr("id", ids);
    }

    public List<Announcement> findByHash(String ...hashes) {
        return findByAttr("hash", hashes);
    }

    public boolean safeInsert(Announcement a) {
        List<Announcement> alreadyExisting = findByHash(a.getHash());
        if (alreadyExisting != null && (!alreadyExisting.isEmpty())) return false;
        this.persist(a);
        return true;
    }

    public boolean allExist(Set<BigInteger> linked) {
        if (linked.size() == 0) return true;
        return findByIds(linked.toArray(new BigInteger[0])).size() == linked.size();
    }
}
