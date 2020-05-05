package pt.ist.meic.sec.dpas.common.model;

import pt.ist.meic.sec.dpas.common.utils.HibernateConfig;

import javax.persistence.Entity;

@Entity
public class GeneralBoard extends Board {

    public GeneralBoard(HibernateConfig config) {
        super(config);
    }

    private GeneralBoard() {}

    @Override
    public String toString() {
        return "GeneralBoard{" +
                "announcements=" + getAnnouncements() +
                '}';
    }
}
