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
    <version>1.0</version>
</dependency>
```

## Usage
``` Java
LE4j.builder()
      .domain("test.domain.tld")
      .useStaging(false)
      .workdir("/path/to/work/at")
      .build()
      .obtainCert();
```
