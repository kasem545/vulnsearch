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
Searching for PoC code for CVE: CVE-2010-0434
References for CVE CVE-2010-0434:
[
  "http://svn.apache.org/viewvc?view=revision&revision=918427",
  "https://bugzilla.redhat.com/show_bug.cgi?id=570171",
  "http://www.securityfocus.com/bid/38494",
  "http://svn.apache.org/viewvc?view=revision&revision=917867",
  "https://issues.apache.org/bugzilla/show_bug.cgi?id=48359",
  "http://httpd.apache.org/security/vulnerabilities_22.html",
  "http://svn.apache.org/viewvc/httpd/httpd/branches/2.2.x/server/protocol.c?r1=917617&r2=917867&pathrev=917867&diff_format=h",
  "http://www.redhat.com/support/errata/RHSA-2010-0168.html",
  "http://www.redhat.com/support/errata/RHSA-2010-0175.html",
  "http://secunia.com/advisories/39628",
  "http://www-01.ibm.com/support/docview.wss?uid=swg1PM12247",
  "http://lists.opensuse.org/opensuse-security-announce/2010-04/msg00006.html",
  "http://secunia.com/advisories/39501",
  "http://lists.fedoraproject.org/pipermail/package-announce/2010-May/040652.html",
  "http://lists.fedoraproject.org/pipermail/package-announce/2010-April/039957.html",
  "http://www.vupen.com/english/advisories/2010/1057",
  "http://secunia.com/advisories/39632",
  "http://www.vupen.com/english/advisories/2010/0911",
  "http://www.vupen.com/english/advisories/2010/0994",
  "http://www.debian.org/security/2010/dsa-2035",
  "http://www.vupen.com/english/advisories/2010/1001",
  "http://secunia.com/advisories/39656",
  "http://secunia.com/advisories/40096",
  "http://www-01.ibm.com/support/docview.wss?uid=swg1PM15829",
  "http://www-01.ibm.com/support/docview.wss?uid=swg1PM08939",
  "http://www.vupen.com/english/advisories/2010/1411",
  "http://secunia.com/advisories/39100",
  "http://secunia.com/advisories/39115",
  "http://lists.vmware.com/pipermail/security-announce/2010/000105.html",
  "http://www.vmware.com/security/advisories/VMSA-2010-0014.html",
  "http://support.apple.com/kb/HT4435",
  "http://lists.apple.com/archives/security-announce/2010//Nov/msg00000.html",
  "http://www.oracle.com/technetwork/topics/security/cpujuly2013-1899826.html",
  "http://marc.info/?l=bugtraq&m=127557640302499&w=2",
  "https://exchange.xforce.ibmcloud.com/vulnerabilities/56625",
  "https://oval.cisecurity.org/repository/search/definition/oval%3Aorg.mitre.oval%3Adef%3A8695",
  "https://oval.cisecurity.org/repository/search/definition/oval%3Aorg.mitre.oval%3Adef%3A10358",
  "https://lists.apache.org/thread.html/r9f93cf6dde308d42a9c807784e8102600d0397f5f834890708bf6920%40%3Ccvs.httpd.apache.org%3E",
  "https://lists.apache.org/thread.html/r0276683d8e1e07153fc8642618830ac0ade85b9ae0dc7b07f63bb8fc%40%3Ccvs.httpd.apache.org%3E",
  "https://lists.apache.org/thread.html/r9e8622254184645bc963a1d47c5d47f6d5a36d6f080d8d2c43b2b142%40%3Ccvs.httpd.apache.org%3E",
  "https://lists.apache.org/thread.html/5df9bfb86a3b054bb985a45ff9250b0332c9ecc181eec232489e7f79%40%3Ccvs.httpd.apache.org%3E",
  "https://lists.apache.org/thread.html/f7f95ac1cd9895db2714fa3ebaa0b94d0c6df360f742a40951384a53%40%3Ccvs.httpd.apache.org%3E",
  "https://lists.apache.org/thread.html/r688df6f16f141e966a0a47f817e559312b3da27886f59116a94b273d%40%3Ccvs.httpd.apache.org%3E",
  "https://lists.apache.org/thread.html/54a42d4b01968df1117cea77fc53d6beb931c0e05936ad02af93e9ac%40%3Ccvs.httpd.apache.org%3E",
  "https://lists.apache.org/thread.html/re2e23465bbdb17ffe109d21b4f192e6b58221cd7aa8797d530b4cd75%40%3Ccvs.httpd.apache.org%3E",
  "https://lists.apache.org/thread.html/r75cbe9ea3e2114e4271bbeca7aff96117b50c1b6eb7c4772b0337c1f%40%3Ccvs.httpd.apache.org%3E",
  "https://lists.apache.org/thread.html/8d63cb8e9100f28a99429b4328e4e7cebce861d5772ac9863ba2ae6f%40%3Ccvs.httpd.apache.org%3E",
  "https://lists.apache.org/thread.html/r5f9c22f9c28adbd9f00556059edc7b03a5d5bb71d4bb80257c0d34e4%40%3Ccvs.httpd.apache.org%3E",
  "https://lists.apache.org/thread.html/r476d175be0aaf4a17680ef98c5153b4d336eaef76fb2224cc94c463a%40%3Ccvs.httpd.apache.org%3E",
  "https://lists.apache.org/thread.html/r57608dc51b79102f3952ae06f54d5277b649c86d6533dcd6a7d201f7%40%3Ccvs.httpd.apache.org%3E",
  "https://lists.apache.org/thread.html/rfbaf647d52c1cb843e726a0933f156366a806cead84fbd430951591b%40%3Ccvs.httpd.apache.org%3E",
  "https://lists.apache.org/thread.html/rb9c9f42dafa25d2f669dac2a536a03f2575bc5ec1be6f480618aee10%40%3Ccvs.httpd.apache.org%3E",
  "https://lists.apache.org/thread.html/rf6449464fd8b7437704c55f88361b66f12d5b5f90bcce66af4be4ba9%40%3Ccvs.httpd.apache.org%3E",
  "https://lists.apache.org/thread.html/r9ea3538f229874c80a10af473856a81fbf5f694cd7f471cc679ba70b%40%3Ccvs.httpd.apache.org%3E",
  "https://lists.apache.org/thread.html/r2cb985de917e7da0848c440535f65a247754db8b2154a10089e4247b%40%3Ccvs.httpd.apache.org%3E",
  "https://lists.apache.org/thread.html/rad2acee3ab838b52c04a0698b1728a9a43467bf365bd481c993c535d%40%3Ccvs.httpd.apache.org%3E",
  "https://lists.apache.org/thread.html/rdca61ae990660bacb682295f2a09d34612b7bb5f457577fe17f4d064%40%3Ccvs.httpd.apache.org%3E",
  "https://lists.apache.org/thread.html/r8828e649175df56f1f9e3919938ac7826128525426e2748f0ab62feb%40%3Ccvs.httpd.apache.org%3E",
  "https://lists.apache.org/thread.html/rad01d817195e6cc871cb1d73b207ca326379a20a6e7f30febaf56d24%40%3Ccvs.httpd.apache.org%3E"
]

```
