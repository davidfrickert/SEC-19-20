package pt.ist.meic.sec.dpas.common.utils.dao;

import java.io.Serializable;
import java.util.List;

public interface IDAO<T, Id extends Serializable> {
    public boolean persist(T entity);

    public void update(T entity);

    public T findById(Id id);

    public void delete(T entity);

    public List<T> findAll();
}
