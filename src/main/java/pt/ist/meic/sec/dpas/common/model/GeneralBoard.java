package pt.ist.meic.sec.dpas.common.model;

import javax.persistence.Entity;

@Entity
public class GeneralBoard extends Board {
    @Override
    public String toString() {
        return "GeneralBoard{" +
                "announcements=" + getAnnouncements() +
                '}';
    }
}
