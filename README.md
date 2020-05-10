# LE4j
acme4j wrapper for easy LE certificate obtaining using builtin webserver

## Usage
``` Java
LE4j.builder()
      .domain("test.domain.tld")
      .useStaging(false)
      .workdir("/path/to/work/at")
      .build()
      .obtainCert();
```
