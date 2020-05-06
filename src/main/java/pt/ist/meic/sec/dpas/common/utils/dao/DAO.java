package pt.ist.meic.sec.dpas.common.utils.dao;

import org.apache.log4j.Logger;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.hibernate.boot.Metadata;
import org.hibernate.boot.MetadataSources;
import org.hibernate.boot.registry.StandardServiceRegistry;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.hibernate.exception.ConstraintViolationException;
import pt.ist.meic.sec.dpas.common.utils.HibernateConfig;

import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import java.io.Serializable;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class DAO<T, ID extends Serializable> implements IDAO<T, ID>{

    private final static Logger logger = Logger.getLogger(DAO.class);

    private final static HibernateConfig config = HibernateConfig.getInstance();

    private Session session;
    private Transaction transaction;
    private Class<T> type;

    public DAO(Class<T> t) {
        this.type = t;
    }

    public boolean persist(final Object o) {
        this.openSessionWithTransaction();
        try {
            session.save(o);
        } catch (ConstraintViolationException sqe) {
            this.rollbackAndClose();
            return false;
        }
        this.commitAndClose();
        return true;
    }

    public void delete(final Object o) {
        this.openSessionWithTransaction();
        session.delete(o);
        this.commitAndClose();
    }

    public void openSession() {
        session = config.getSessionFactory().openSession();
    }

    @Override
    public void update(T entity) {
        this.openSessionWithTransaction();
        session.update(entity);
        this.commitAndClose();
    }

    @Override
    public T findById(ID id) {
        openSession();
        T t = session.get(type, id);
        closeSession();
        return t;
    }

    @Override
    public List<T> findAll() {
        openSessionWithTransaction();
        CriteriaBuilder cb = session.getCriteriaBuilder();
        CriteriaQuery<T> c = cb.createQuery(type);
        c.from(type);
        List<T> all = session.createQuery(c).getResultStream().collect(Collectors.toList());
        commitAndClose();
        return all;
    }

    public Stream<T> findAllAsStream() {
        return findAll().stream();
    }

    public void openSessionWithTransaction() {
        if (transaction != null && transaction.isActive()) {
            logger.info("Attempt to create new session with a transaction still active... Forgot to close transaction?");
        }
        if (session == null || !session.isOpen())
            openSession();
        transaction = session.beginTransaction();
    }

    protected void commitAndClose() {
        transaction.commit();
        session.close();
    }

    protected void rollbackAndClose() {
        transaction.rollback();
        session.close();
    }

    public Session getCurrentSession() {
        return config.getSession();
    }

    public Class<T> getType() {
        return type;
    }

    private void closeSession() {
        session.close();
    }
}
