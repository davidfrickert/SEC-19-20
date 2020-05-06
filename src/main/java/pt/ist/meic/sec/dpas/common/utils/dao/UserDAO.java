package pt.ist.meic.sec.dpas.common.utils.dao;

import org.hibernate.Session;
import pt.ist.meic.sec.dpas.common.model.User;

import javax.persistence.NoResultException;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Predicate;
import javax.persistence.criteria.Root;

public class UserDAO extends DAO<User, Integer> {
    public UserDAO() {
        super(User.class);
    }

    public User findByName(String attr, Object value) {
        openSessionWithTransaction();
        Session session = getCurrentSession();
        CriteriaBuilder cb = session.getCriteriaBuilder();
        CriteriaQuery<User> query = cb.createQuery(getType());
        Root<User> root = query.from(getType());
        Predicate nameMatches = cb.equal(root.get(attr), value);
        query.select(root).where(nameMatches);
        try {
            User u = session.createQuery(query).getSingleResult();
            commitAndClose();
            return u;
        } catch (NoResultException e) {
            rollbackAndClose();
            return null;
        }
    }

    public boolean exists(String attr, Object value) {
        return findByName(attr, value) != null;
    }
}
