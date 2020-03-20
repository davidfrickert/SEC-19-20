package pt.ist.meic.sec.dpas.common.utils;

import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.hibernate.boot.Metadata;
import org.hibernate.boot.MetadataSources;
import org.hibernate.boot.registry.StandardServiceRegistry;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;

public class DAO {

    private static final SessionFactory sf;
    static {
        StandardServiceRegistry ssr = new StandardServiceRegistryBuilder().configure("hibernate.cfg.xml").build();
        Metadata meta = new MetadataSources(ssr).getMetadataBuilder().build();
        sf = meta.getSessionFactoryBuilder().build();
    }

    public static void persist(final Object o) {
        System.out.println("persisiting: " + o);
        Session s = openSession();
        Transaction t = s.beginTransaction();
        s.save(o);
        t.commit();
        s.close();
    }

    public static void delete(final Object o) {
        sf.getCurrentSession().delete(o);
    }

    /*
    public static <T> Stream<T> getAllAsStream(final Class<T> type) {
        Session session = sf.getCurrentSession();
        session.beginTransaction();
        CriteriaBuilder cb = session.getCriteriaBuilder();
        CriteriaQuery<T> c = cb.createQuery(type);
        c.from(type);
        Stream <T> data = session.createQuery(c).getResultStream();
        session.getTransaction().commit();
        return data;
    }

    public static <T> List<T> getAllAsList(final Class<T> type) {
        return getAllAsStream(type).collect(Collectors.toList());
    }
    public static <K, V> Map<K, V> getAllAsMap(final Class<V> type) {
        return getAllAsStream(type).collect(Collectors.toMap(v -> (K) sf.getPersistenceUnitUtil().getIdentifier(v), v -> v));
    }


     */


    public static SessionFactory getSf() {
        return sf;
    }

    public static Session openSession() {
        return sf.openSession();
    }
}
