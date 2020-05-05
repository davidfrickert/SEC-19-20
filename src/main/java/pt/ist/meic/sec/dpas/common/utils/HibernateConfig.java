package pt.ist.meic.sec.dpas.common.utils;

import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;
import pt.ist.meic.sec.dpas.common.model.*;

import java.util.Properties;

public class HibernateConfig {

    private Configuration configuration;
    private SessionFactory sessionFactory;
    private Session session;

    public HibernateConfig(int port) {
        configuration = new Configuration();
        Properties properties = new Properties();
        properties.put("hibernate.dialect", "org.hibernate.dialect.MySQLDialect");
        properties.put("hibernate.connection.driver_class", "com.mysql.jdbc.Driver");
        properties.put("hibernate.connection.url", "jdbc:mysql://localhost/dpas?createDatabaseIfNotExist=true");
        properties.put("hibernate.connection.username", "root");
        properties.put("hibernate.connection.password", "root");
        properties.put("hibernate.hbm2ddl.auto", "create-drop");
        properties.put("hibernate.current_session_context_class", "thread");
        properties.put("hibernate.enable_lazy_load_no_trans", "true");
        properties.put("show_sql", "false");
        configuration.setProperties(properties);
        configuration.addAnnotatedClass(User.class);
        configuration.addAnnotatedClass(Announcement.class);
        configuration.addAnnotatedClass(Board.class);
        configuration.addAnnotatedClass(UserBoard.class);
        configuration.addAnnotatedClass(GeneralBoard.class);
        configuration.addAnnotatedClass(PayloadHistory.class);

        sessionFactory = configuration.buildSessionFactory();
        session = sessionFactory.openSession();
    }

    public void closeSessionFactory() {
        session.close();
        sessionFactory.close();
    }

    public Session getSession() {
        if (session == null || !session.isOpen())
            session = sessionFactory.openSession();
        return session;
    }

    public SessionFactory getSessionFactory() {
        return sessionFactory;
    }
}
