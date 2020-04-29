Welcome to the CyberSecurity-Playground wiki!

A good reference for my CyberSecurity Playground

**IP Addresses Blocking**
 
`@echo off`
`if "%1"=="list" (`
  `netsh advfirewall firewall show rule Blockit | findstr RemoteIP`
  `exit/b`
`)`

`:: Deleting existing block on ips`
`netsh advfirewall firewall delete rule name="Blockit"`

`:: Block new ips (while reading them from blockit.txt)`
`for /f %%i in (blockit.txt) do (`
  `netsh advfirewall firewall add rule name="Blockit" protocol=any dir=in action=block remoteip=%%i`
  `netsh advfirewall firewall add rule name="Blockit" protocol=any dir=out action=block remoteip=%%i`
`)`

`:: call this batch again with list to show the blocked IPs`
`call %0 list`

a. Create a blockit.txt with your IPs to block and run blockit.

b. You can run blockit list to check which IPs are blocked at the moment.

Note: This needs to be run as Administrator.

Note: if you wanted outgoing or incoming traffic blocked so we added both dir=in and dir=out. We can delete one or the other (or leave them both for both directions).

**Vulnerability Management**
1. [Vfeed](https://vfeed.io/)
2. [Proactive Detection Content of Specific Vulnerability Mapped Against ATT&CK Sigma](https://medium.com/@ab_65156/proactive-detection-content-cve-2019-0708-vs-mitre-att-ck-sigma-elastic-and-arcsight-22f9ebae7d82)
3. [CVE-2020-0683 - Windows MSI “Installer service” Elevation of Privilege](https://github.com/padovah4ck/CVE-2020-0683)

**DDoS**
1. [ICMP Flooding](https://www.netresec.com/index.ashx?page=Blog&month=2016-11&post=BlackNurse-Denial-of-Service-Attack)
2. [Cache Poisoned DoS](https://cpdos.org/)

**Pentesting & Defending**
1. [Introduction to Pentesting](https://github.com/klks/Introduction_to_pentesting)
2. [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
3. [Passive Recon & Asset Discovery](https://delta.navisec.io/osint-for-pentesters-part-1-passive-recon-and-asset-discovery/)
4. [OWASP Nettacker](https://github.com/zdresearch/OWASP-Nettacker)
5. [Active Directory Attack & Defense](https://github.com/infosecn1nja/AD-Attack-Defense)
6. [Windows 10 Recommended Block Rules](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules)
7. [Application Whitelisting Bypass (DotNet)](https://bohops.com/2019/08/19/dotnet-core-a-vector-for-awl-bypass-defense-evasion/)
8. [DLL Auto Execution Technique](https://docs.microsoft.com/en-us/windows/win32/dlls/dllmain)
9. [OSCP Resources](https://github.com/0x4D31/awesome-oscp)
10. [Powershell Obfuscation using Secure String](https://www.wietzebeukema.nl/blog/powershell-obfuscation-using-securestring)
11. [Sigma Rules](https://github.com/Neo23x0/sigma)
12. [Windows Red Team Cheat Sheet](https://morph3sec.com/Cheat-Sheets/Windows-Red-Team-Cheat-Sheet/)
13. [Evasion Techniques](https://evasions.checkpoint.com/)
14. [Windows Privilege Escalation Guide](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
15. [Heaven Gate Technique on Linux](https://redcanary.com/blog/heavens-gate-technique-on-linux/)
16. [Pivoting Guide](https://artkond.com/2017/03/23/pivoting-guide/#icmp-tunneling)
17. [Using SRDI to Bypass AV & EDR](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/)
18. [File Upload Vulnerability Scanner and Exploitation Tool](https://github.com/almandin/fuxploider)
19. [Windows Server 2008R2-2019 NetMan DLL Hijacking](https://itm4n.github.io/windows-server-netman-dll-hijacking/)

**Malware**
1. [0 day malware prevention / detection](https://www.slideshare.net/mobile/mynog/zero-day-malware-detectionprevention-using-open-source-software)
2. [Ransomware Protection and Containment Strategies](https://www.fireeye.com/content/dam/fireeye-www/current-threats/pdfs/wp-ransomware-protection-and-containment-strategies.pdf)
3. [Understanding Malware](https://maxkersten.nl/wp-content/uploads/2018/11/Understanding-Malware.pdf)
4. [Multi-Platform Malware](https://maxkersten.nl/wp-content/uploads/2018/11/Multi-platform-Malware.pdf)
5. [Google Play BankBot Trojan 0 detection](https://www.threatfabric.com/blogs/sophisticated_google_play_bankbot_trojan_campaigns.html)
6. [Android Two Stages Decryption](https://maxkersten.nl/wp-content/uploads/2018/11/MalwareAnalyse.pdf)
7. [Multiple Platform Malware Databases](https://github.com/ThisIsLibra/MalPull)
8. [Ransomware Builder](https://github.com/qH0sT/Ransomware-Builder-v3.0)
9. [Weaponize Legitimate PE](https://medium.com/@bigb0ss/expdev-weaponizing-your-favorite-pe-portable-executable-exploit-c268c0c076c7)
10. [Emotet-Havoc Wreaking Malware](https://www.cert.pl/en/news/single/whats-up-emotet/)
11. [Rank Strings Output Speedier Malware Analysis](https://www.youtube.com/watch?v=pLiaVzOMJSk&feature=youtu.be)
12. [Malware Analysis Fundamentals - Files & Tools](https://www.winitor.com/pdf/Malware-Analysis-Fundamentals-Files-Tools.pdf)
13. [Manual Dridex Dropper Malicious Document Deobfuscation Methods](https://blog.rapid7.com/2020/04/17/uncooking-eggs-manual-dridex-dropper-malicious-document-deobfuscation-methods/amp/)

**Reversing**
1. [Dissected PE Breakthrough](http://web.cse.ohio-state.edu/~reeves.92/CSE2421/HelloWorldGoal.pdf)
2. [Reversing for Beginners](https://beginners.re/)
3. [Deobfuscating APT Flow Graphs with cutter and radare2](https://research.checkpoint.com/2019/deobfuscating-apt32-flow-graphs-with-cutter-and-radare2/)
4. [Advanced Binary Deobfuscation](https://github.com/malrev/ABD/blob/master/README.md)

**Threat Intelligence**
1. _Empowering Hypotesis_
2. _Strategic Reporting_
3. [Guide To Cyber Threat Intelligence](https://cryptome.org/2015/09/cti-guide.pdf)
4. [Reporting Template](https://zeltser.com/cyber-threat-intel-and-ir-report-template/)
5. [RecordedFuture Threat Intelligence Handbook](https://go.recordedfuture.com/hubfs/ebooks/threat-intelligence-handbook.pdf?utm_campaign=THR-BOO&utm_source=hs_automation&utm_medium=email&utm_content=66359789&_hsenc=p2ANqtz--5xAoze0C0CkgQPW-HntN85YBy26hFwMeAsTcl2y5KL2WHbU_z2mdXPdDTGUjTLUpwghyd3UVWOztRhSjcyKKn5YRIyw&_hsmi=66359789)
6. [How Threat Intelligence Helps Organizations](https://www.threathunting.se/2019/11/21/threat-intelligence/)

**Audit and Automated Framework**
1. [Chef Inspec](https://www.inspec.io/)

**Threat Hunting**
1. [MageCart](https://censys.io/blog/magecart-threat-hunting-edition)
2. [DNS over HTTPS](https://blog.redteam.pl/2019/04/dns-based-threat-hunting-and-doh.html?m=1)
3. [Hunting TA with TLS Cert](https://mpars0ns.github.io/archc0n-2016-tls-slides/#/17)
4. [Hunting for Privilege Escalation](https://www.slideshare.net/heirhabarov/hunting-for-privilege-escalation-in-windows-environment)

**Log Management**
1. [Windows Powershell Logging Cheat Sheet](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5ba3dc87e79c703f9bfff29a/1537465479833/Windows+PowerShell+Logging+Cheat+Sheet+ver+Sept+2018+v2.2.pdf)
2. 

**Digital Forensic and Incident Response (DFIR)**
1. [Banking Trojan](https://articles.forensicfocus.com/2019/05/06/following-the-rtm-forensic-examination-of-a-computer-infected-with-a-banking-trojan/)
2. [DFIR Cheat Sheet](https://www.jaiminton.com/cheatsheet/DFIR/)
3. [Volatility Workbench](https://www.osforensics.com/tools/volatility-workbench.html)
4. [Incident Handling Automation Project](https://github.com/certtools/intelmq)

**Scripting**
1. [Lazy Script Kali Linux](https://hakin9.org/the-lazy-script-will-make-your-life-easier-and-of-course-faster/)
2. [OSINT-Probe Spider](https://github.com/Aravindha1234u/Probe_spider)

**CyberSecurity Framework**
1. [NIST](https://www.praxiom.com/nist.htm)

**Misc**
1. [Moloch Full Packet Capture](https://molo.ch/)
