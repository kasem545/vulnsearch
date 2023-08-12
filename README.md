# vulnsearch

this tools use shodan to find vulnerabilities of a webserver and it looks for possible POC "Proof of concept"


# Usage
```
echo "example.com" |bash vulnsearch.sh
```
```
chmod +x vulnsearch.sh
./vulnsearch.sh
```
# Test Sample 
```
echo "redacted.co.il" |bash vulnsearch.sh                                                                                                                                              ─╯
[*] vulnsearch
Retrieved IP address:  ###.###.###.###
{
  "cpes": [
    "cpe:/a:openbsd:openssh:3.9p1",
    "cpe:/a:apache:http_server:2.0.59"
  ],
  "hostnames": [
    "###.###.###.###"
  ],
  "ip": "###.###.###.###",
  "ports": [
    22,
    80
  ],
  "tags": [],
  "vulns": [
    "CVE-2021-39275",
    "CVE-2010-0434",
    "CVE-2013-1862",
    "CVE-2017-9798",
    "CVE-2022-30556",
    "CVE-2007-6203",
    "CVE-2017-9788",
    "CVE-2015-0228",
    "CVE-2007-3303",
    "CVE-2022-22721",
    "CVE-2007-3304",
    "CVE-2011-3607",
    "CVE-2008-0005",
    "CVE-2021-40438",
    "CVE-2009-3094",
    "CVE-2022-28614",
    "CVE-2008-2364",
    "CVE-2008-2384",
    "CVE-2021-34798",
    "CVE-2014-0231",
    "CVE-2022-28330",
    "CVE-2007-5000",
    "CVE-2022-22719",
    "CVE-2009-1891",
    "CVE-2007-6750",
    "CVE-2011-4415",
    "CVE-2012-0031",
    "CVE-2011-3192",
    "CVE-2009-3555",
    "CVE-2008-2939",
    "CVE-2022-22720",
    "CVE-2022-31813",
    "CVE-2015-3183",
    "CVE-2018-1301",
    "CVE-2007-6388",
    "CVE-2010-0425",
    "CVE-2011-4317",
    "CVE-2021-44790",
    "CVE-2011-0419",
    "CVE-2008-2168",
    "CVE-2022-29404",
    "CVE-2009-1195",
    "CVE-2009-3095",
    "CVE-2016-8612",
    "CVE-2011-3639",
    "CVE-2007-4465",
    "CVE-2011-3368",
    "CVE-2018-1303",
    "CVE-2018-1302",
    "CVE-2022-28615",
    "CVE-2006-20001",
    "CVE-2007-3847",
    "CVE-2022-37436",
    "CVE-2012-0053",
    "CVE-2006-5752"
  ]
}
Searching for PoC code for CVE: CVE-2017-9798
References for CVE CVE-2017-9798:
[
  "https://security-tracker.debian.org/tracker/CVE-2017-9798",
  "https://github.com/hannob/optionsbleed",
  "https://blog.fuzzing-project.org/uploads/apache-2.2-optionsbleed-backport.patch",
  "https://blog.fuzzing-project.org/60-Optionsbleed-HTTP-OPTIONS-method-can-leak-Apaches-server-memory.html",
  "http://openwall.com/lists/oss-security/2017/09/18/2",
  "https://svn.apache.org/viewvc/httpd/httpd/branches/2.4.x/server/core.c?r1=1805223&r2=1807754&pathrev=1807754&view=patch",
  "https://www.exploit-db.com/exploits/42745/",
  "http://www.securitytracker.com/id/1039387"
]

Searching for PoC code for CVE: CVE-2021-39275
References for CVE CVE-2021-39275:
[
  "https://httpd.apache.org/security/vulnerabilities_24.html",
  "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SPBR6WUYBJNACHKE65SPL7TJOHX7RHWD/",
  "https://lists.apache.org/thread.html/r82c077663f9759c7df5a6656f925b3ee4f55fcd33c889ba7cd687029@%3Cusers.httpd.apache.org%3E",
  "https://lists.apache.org/thread.html/r82838efc5fa6fc4c73986399c9b71573589f78b31846aff5bd9b1697@%3Cusers.httpd.apache.org%3E",
  "https://lists.apache.org/thread.html/r3925e167d5eb1c75def3750c155d753064e1d34a143028bb32910432@%3Cusers.httpd.apache.org%3E",
  "https://lists.apache.org/thread.html/r61fdbfc26ab170f4e6492ef3bd5197c20b862ce156e9d5a54d4b899c@%3Cusers.httpd.apache.org%3E",
  "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZNCYSR3BXT36FFF4XTCPL3HDQK4VP45R/",
  "https://lists.debian.org/debian-lts-announce/2021/10/msg00001.html",
  "https://security.netapp.com/advisory/ntap-20211008-0004/",
  "https://www.debian.org/security/2021/dsa-4982",
  "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-httpd-2.4.49-VWL69sWQ",
  "https://www.oracle.com/security-alerts/cpujan2022.html",
  "https://www.oracle.com/security-alerts/cpuapr2022.html",
  "https://cert-portal.siemens.com/productcert/pdf/ssa-685781.pdf",
  "https://security.gentoo.org/glsa/202208-20"
]

```
