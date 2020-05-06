package pt.ist.meic.sec.dpas.common.utils;

import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;
import pt.ist.meic.sec.dpas.common.model.*;
import pt.ist.meic.sec.dpas.server.ServerLauncher;

import javax.xml.transform.Result;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Properties;
import java.util.Random;

public class HibernateConfig {

    private static ThreadLocal<HibernateConfig> config = ThreadLocal.withInitial(HibernateConfig::new);
    private static ServerLauncher sl = ServerLauncher.getInstance();

    private Configuration configuration;
    private SessionFactory sessionFactory;
    private Session session;

    private HibernateConfig() {

        int db_int;
        if (sl != null) {
            db_int = sl.launched;
        }
        else {
            db_int = 0;
        }

        configuration = new Configuration();
        Properties properties = new Properties();
        properties.put("hibernate.dialect", "org.hibernate.dialect.MySQL5Dialect");
        properties.put("hibernate.connection.driver_class", "com.mysql.jdbc.Driver");
        properties.put("hibernate.connection.url", "jdbc:mysql://localhost/dpas" + db_int + "?createDatabaseIfNotExist=true");
        properties.put("hibernate.connection.username", "root");
        properties.put("hibernate.connection.password", "root");
        properties.put("hibernate.hbm2ddl.auto", "update");
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
        return this.sessionFactory;
    }

    public static synchronized HibernateConfig getInstance() {
        if (config.get() == null) {
            config.set(new HibernateConfig());
        }
        return config.get();
    }

//    public static void main(String[] args) {
//        HibernateConfig config = HibernateConfig.getInstance();
//        System.out.println(config.getSession());
//    }
}
