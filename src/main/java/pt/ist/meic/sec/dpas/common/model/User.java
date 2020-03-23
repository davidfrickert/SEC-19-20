package pt.ist.meic.sec.dpas.common.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import java.security.PublicKey;

@Entity
public class User{

    @Column(columnDefinition = "VARBINARY(4096)", nullable = false)
    private PublicKey publicKey;

    @Column
    private String name;

    public User(PublicKey publicKey, String name){
        this.name = name;
        this.publicKey = publicKey;
    }




}