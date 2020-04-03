# SEC-19-20
Dependable Public Announcement Server

## Build and run with Linux terminal

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

3. Run server: `mvn exec:java@default-cli`

4. Run client: `mvn exec:java@client -Dexec.args="[username] [keypath] [keyStorePassword]"`\
Example: `mvn exec:java@client  -Dexec.args="test1 keys/private/clients/1.p12 client1"`

### Run tests

1. Go to the root folder of the project.

2. Compile maven build: `mvn clean compile`

3. Run specification tests: `mvn test -Dtest=Requisites`

4. Run Attacker tests: `mvn test -Dtest=Attacks`\
\
Or run all tests with `mvn test`.


