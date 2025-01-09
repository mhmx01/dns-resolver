### usage
```
$ ./main.py -h
usage: main.py [-h] domain

query the ip address for a given domain name.

positional arguments:
  domain      the domain to query.

options:
  -h, --help  show this help message and exit


$ ./main.py nostarch.com
querying 198.41.0.4 for nostarch.com
querying 192.41.162.30 for nostarch.com
querying 108.162.192.82 for nostarch.com
{'rname': 'nostarch.com', 'rtype': 1, 'rclass': 1, 'ttl': 300, 'rdlength': 4, 'rdata': '104.20.18.121'}
{'rname': 'nostarch.com', 'rtype': 1, 'rclass': 1, 'ttl': 300, 'rdlength': 4, 'rdata': '104.20.17.121'}
```


### objectives
- re-create some the of cli tools that're commonly used (eg. dig, nslookup).
- build something that implement a specific protocol or an RFC.
- practice socket/network programming


### todo
- [ ] support other record types (eg. CNAME)
- [ ] split into multiple modules
- [ ] format/lint using ruff (editor plugin, pre-commit)
