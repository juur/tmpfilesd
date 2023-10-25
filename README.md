# tmpfilesd #

## About ##
`tmpfilesd` is a replacement for `systemd-tmpfiles` that does not require systemd and includes support for sysvinit style enviroments

## Building ##

From source:

```bash
./configure && make
```

From the source, for RHEL/CentOS:

```bash
./configure && make dist && rpmbuild -ta tmpfilesd*.tar.gz
```

## References ##
Uses some code from <https://github.com/troglobit/libite>, specifically: `mkpath()`.

![CodeQL](https://github.com/juur/tmpfilesd/actions/workflows/github-code-scanning/codeql/badge.svg)
