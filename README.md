# LE4j
ACME client for obtaining lets encrypt certificates as keystore.

## Maven
With jitpack you can use LE4j in your maven project.
```
<repositories>
      <repository>
          <id>jitpack.io</id>
          <url>https://jitpack.io</url>
      </repository>
</repositories>
```
```
<dependency>
    <groupId>com.github.ChillUpX</groupId>
    <artifactId>LE4j</artifactId>
    <version>1.1</version>
</dependency>
```

## Usage
``` Java
LE4j.builder()
          .accountKeyPath("/path/to/account/key/folder")
          .domainKeyPath("/path/to/domain/key/folder")
          .domainCertPath("/path/to/domain/crt/folder")
          .domainKeystorePath("/path/to/keystore/folder")
          .domain("domain.tld")
          .organisation("organisation")
          .keystorePassword("secret")
          .keySize(2048) //Optional
          .timeBetweenRetry(3000L) //Optional
          .useStaging(false) //Optional
          .writeCsrToFile(false) //Optional
          .build()
      .obtainCert();
```

## License

_LE4j_ is open source software. The source code is distributed under the terms of [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0).
