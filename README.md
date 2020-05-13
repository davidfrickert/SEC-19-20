# SEC-19-20
Dependable Public Announcement Server

## Build and run with Ubuntu terminal

### Requirements:
```
Java Development Kit 13
Maven
MySQL
```
These packages can be installed using the following commands:
```
sudo add-apt-repository ppa:linuxuprising/java
sudo apt-get update
sudo apt-get install oracle-java13-installer

sudo apt install maven

sudo apt install mysql-server
mysql_secure_installation
```


You can check if the required packages are installed using:
```
mvn -v
mysql -V
java --version
```

Make sure to have a MySQL user with the following credentials:
```
Username: root
Password: root
```

Finally, access MySQL with `mysql -u root -p` and set a timezone. For example:
```
SET GLOBAL time_zone = '+1:00';
\q
```

### Run client and server separately

1. Go to the root folder of the project.

2. Compile maven build: `mvn clean compile`

3. Launch servers: `mvn exec:java@server -Dexec.args="[port] [keypath] [keyStorePassword]"`\
Examples:
```
mvn exec:java@server -Dexec.args="35000 keys/private/server/keystore1.p12 server1"
mvn exec:java@server -Dexec.args="35001 keys/private/server/keystore2.p12 server2"
mvn exec:java@server -Dexec.args="35002 keys/private/server/keystore3.p12 server3"
mvn exec:java@server -Dexec.args="35003 keys/private/server/keystore4.p12 server4"
mvn exec:java@server -Dexec.args="35004 keys/private/server/keystore5.p12 server5"
```

4. Launch clients: `mvn exec:java@client -Dexec.args="[username] [keypath] [keyStorePassword] [baseServerPort]"`\
Examples:
```
mvn exec:java@client -Dexec.args="test1 keys/private/clients/1.p12 client1 35000"
mvn exec:java@client -Dexec.args="test2 keys/private/clients/2.p12 client2 35000"
mvn exec:java@client -Dexec.args="test3 keys/private/clients/3.p12 client3 35000"
```

### Run tests

1. Go to the root folder of the project.

2. Compile maven build: `mvn clean compile`

3. Launch servers manually (as described in previous section)

3. Run specification tests: `mvn test -Dtest=Requisites`

4. Run Attacker tests: `mvn test -Dtest=Attacks`\
Or run all tests with `mvn test`.

NOTE: Some test assertions are only useful if the databases are clean. You can run the following script:

```
mysql -u root -proot -e "show databases" -s |
    egrep "dpas" |
    xargs -I "@@" mysql -u root -proot -e "DROP DATABASE @@"
```

Or change the Hibernate configuration settings in `pt.ist.meic.sec.dpas.common.utils.HibernateConfig`:

Change the line
```
properties.put("hibernate.hbm2ddl.auto", "update");
```
To
```
properties.put("hibernate.hbm2ddl.auto", "create");
```


