package pt.ist.meic.sec.dpas.common.utils;

import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;
import pt.ist.meic.sec.dpas.common.model.*;

import javax.xml.transform.Result;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Properties;
import java.util.Random;

public class HibernateConfig {

    private static ThreadLocal<HibernateConfig> config = null;
    private Configuration configuration;
    private SessionFactory sessionFactory;
    private Session session;

    private HibernateConfig() {

// // Generate sequential name        
//        String url = "jdbc:mysql://localhost/";
//        String user = "root";
//        String password = "root";
//        int db_int = 0;
//
//        try {
//            Connection con = DriverManager.getConnection(url, user, password);
//            ResultSet rs = con.getMetaData().getCatalogs();
//            while (rs.next()) {
//                String catalogs = rs.getString(1);
//                if (catalogs.equals("dpas"+db_int)) {
//                    db_int++;
//                }
//            }
//        } catch (SQLException e) {
//            e.printStackTrace();
//        }

// Generate random name
        Random rand = new Random();
        int db_int = rand.nextInt(10000);

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

    public static ThreadLocal<HibernateConfig> getInstance() {
        if (config == null) {
            config = new ThreadLocal<>();
            config.set(new HibernateConfig());
        }
        return config;
    }

//    public static void main(String[] args) {
//        HibernateConfig config = HibernateConfig.getInstance();
//        System.out.println(config.getSession());
//    }
}
