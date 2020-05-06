package pt.ist.meic.sec.dpas.common.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import java.io.Serializable;
import java.security.PublicKey;

@Entity
public class User implements Serializable {

    @Id
    @GeneratedValue
    @Column
    private Integer id;

    @Column(columnDefinition = "VARBINARY(4096)")
    private PublicKey publicKey;

    @Column(unique = true)
    private String username;

    private User() {}

    public User(PublicKey publicKey, String username){
        this.username = username;
        this.publicKey = publicKey;
    }

    public Integer getId(){
        return id;
    }

    public PublicKey getPublicKey(){
        return this.publicKey;
    }

    public String getUsername(){
        return this.username;
    }




}