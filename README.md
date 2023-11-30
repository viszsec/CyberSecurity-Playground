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

**Vulnerability Management/Research**
1. [Vfeed](https://vfeed.io/)
2. [Proactive Detection Content of Specific Vulnerability Mapped Against ATT&CK Sigma](https://medium.com/@ab_65156/proactive-detection-content-cve-2019-0708-vs-mitre-att-ck-sigma-elastic-and-arcsight-22f9ebae7d82)
3. [CVE-2020-0683 - Windows MSI “Installer service” Elevation of Privilege](https://github.com/padovah4ck/CVE-2020-0683)
4. [PrintDemon: Print Spooler Privilege Escalation, Persistence & Stealth (CVE-2020-1048 & more)](https://windows-internals.com/printdemon-cve-2020-1048/)
5. [SMBGhost pre-auth RCE abusing Direct Memory Access structs](https://ricercasecurity.blogspot.com/2020/04/ill-ask-your-body-smbghost-pre-auth-rce.html?m=1)
6. [Cmd Hijack - a command/argument confusion with path traversal in cmd.exe](https://hackingiscool.pl/cmdhijack-command-argument-confusion-with-path-traversal-in-cmd-exe/)
7. [OpenCVE Vuln Alerts](https://www.opencve.io/welcome)
8. [Continuous Vuln Scanner - NERVE](https://github.com/PaytmLabs/nerve)

**DDoS**
1. [ICMP Flooding](https://www.netresec.com/index.ashx?page=Blog&month=2016-11&post=BlackNurse-Denial-of-Service-Attack)
2. [Cache Poisoned DoS](https://cpdos.org/)

**Offense & Defense**
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
20. [Breaking Typical Windows Hardening Implementations](https://www.trustedsec.com/blog/breaking-typical-windows-hardening-implementations)
21. [Curated SecTools](https://tools.tldr.run/)
22. [APTSimulator](https://github.com/NextronSystems/APTSimulator/tree/master)
23. [ezEmu](https://github.com/jwillyamz/ezEmu)
24. [Sharp-Suite](https://github.com/FuzzySecurity/Sharp-Suite)
25. [RustScan - Modern Port Scanner](https://github.com/RustScan/RustScan)
26. [Shodan Pentest Guide](https://community.turgensec.com/shodan-pentesting-guide/)
27. [SSRF — Server Side Request Forgery (Types and ways to exploit it)](https://medium.com/@madrobot/ssrf-server-side-request-forgery-types-and-ways-to-exploit-it-part-3-b0f5997e3739)
28. [Demo – Illicit Consent Grant Attack In Azure AD / Office 365](https://www.nixu.com/blog/demonstration-illicit-consent-grant-attack-azure-ad-office-365)
29. [Fast TCP tunnel, transported over HTTP, secured via SSH](https://cybermeisam.medium.com/red-teaming-fast-tcp-tunnel-transported-over-http-secured-via-ssh-what-else-do-we-need-831d13811874)
30. [WAF Evasion](https://blog.isec.pl/waf-evasion-techniques/)
31. [TREVORspray is a modular password sprayer with threading, SSH proxying, loot modules, and more!](https://github.com/blacklanternsecurity/TREVORspray)
32. [Azure Outlook C2](https://github.com/boku7/azureOutlookC2)
33. [Impulsive DLL Hijack](https://github.com/knight0x07/ImpulsiveDLLHijack)
34. [AzureAD ATT/DEF](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense)
35. [Simple ShellCode](https://github.com/plackyhacker/Shellcode-Encryptor)
36. [Full DLL Unhooking CSharp](https://github.com/Kara-4search/FullDLLUnhooking_CSharp)
37. [Windows API Hashing](https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware)
38. [Pass Stealing NPPSPY](https://github.com/gtworek/PSBits/tree/master/PasswordStealing/NPPSpy)

**Malware Related**
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
14. [When Anti-Virus Engines Look Like Kernel Rootkits](https://volatility-labs.blogspot.com/2020/05/when-anti-virus-engines-look-like.html)
15. [First-ever malware strain spotted abusing new DoH (DNS over HTTPS) protocol](https://www.zdnet.com/article/first-ever-malware-strain-spotted-abusing-new-doh-dns-over-https-protocol/)
16. [Hiding your .NET - COMPlus_ETWEnabled](https://blog.xpnsec.com/hiding-your-dotnet-complus-etwenabled/)
17. [theZoo - A Live Malware Repository](https://github.com/ytisf/theZoo)
18. [NetLoader](https://github.com/Flangvik/NetLoader)
19. [PE-SIEVE](https://github.com/hasherezade/pe-sieve)
20. [DLL Proxy Loading Your Favourite C# Implant](https://redteaming.co.uk/2020/07/12/dll-proxy-loading-your-favorite-c-implant/)
21. [Codex Gigas malware DNA profiling](https://github.com/codexgigassys/codex-backend)
22. [Memory Hunter](https://github.com/marcosd4h/memhunter)
23. [RE the Emotet](https://cert.grnet.gr/en/blog/reverse-engineering-emotet/)

**Reversing**
1. [Dissected PE Breakthrough](http://web.cse.ohio-state.edu/~reeves.92/CSE2421/HelloWorldGoal.pdf)
2. [Reversing for Beginners](https://beginners.re/)
3. [Deobfuscating APT Flow Graphs with cutter and radare2](https://research.checkpoint.com/2019/deobfuscating-apt32-flow-graphs-with-cutter-and-radare2/)
4. [Advanced Binary Deobfuscation](https://github.com/malrev/ABD/blob/master/README.md)
5. [Finding executables prone to DLL hijacking](https://github.com/MojtabaTajik/Robber)
6. [Converting an EXE to a DLL](https://osandamalith.com/2019/08/26/converting-an-exe-to-a-dll/)

**Threat Intelligence**
1. [Guide To Cyber Threat Intelligence](https://cryptome.org/2015/09/cti-guide.pdf)
2. [Reporting Template](https://zeltser.com/cyber-threat-intel-and-ir-report-template/)
3. [RecordedFuture Threat Intelligence Handbook](https://go.recordedfuture.com/hubfs/ebooks/threat-intelligence-handbook.pdf?utm_campaign=THR-BOO&utm_source=hs_automation&utm_medium=email&utm_content=66359789&_hsenc=p2ANqtz--5xAoze0C0CkgQPW-HntN85YBy26hFwMeAsTcl2y5KL2WHbU_z2mdXPdDTGUjTLUpwghyd3UVWOztRhSjcyKKn5YRIyw&_hsmi=66359789)
4. [How Threat Intelligence Helps Organizations](https://www.threathunting.se/2019/11/21/threat-intelligence/)
5. [Tracking user location from IP address using Google API](https://medium.com/@n0tty/tracking-any-user-location-with-ip-address-using-google-api-9b58d8c62f89)
6. [CTI is Better Served with Context: Getting better value from IOCs](https://klrgrz.medium.com/cti-is-better-served-with-context-getting-better-value-from-iocs-496343741f80)
7. [Lupo — Malware IOC Extractor](https://malienist.medium.com/lupo-malware-ioc-extractor-cc86ae76b85d)
8. [OSINT VM](https://www.tracelabs.org/initiatives/osint-vm)
9. [Real Intelligence Threat Analytics](https://www.activecountermeasures.com/free-tools/rita/)
10. [Semi-Auto OSINT](https://sn0int.com/)

**Audit, Automated Framework**
1. [Chef Inspec](https://www.inspec.io/)

**Threat Hunting**
1. [MageCart](https://censys.io/blog/magecart-threat-hunting-edition)
2. [DNS over HTTPS](https://blog.redteam.pl/2019/04/dns-based-threat-hunting-and-doh.html?m=1)
3. [Hunting TA with TLS Cert](https://mpars0ns.github.io/archc0n-2016-tls-slides/#/17)
4. [Hunting for Privilege Escalation](https://www.slideshare.net/heirhabarov/hunting-for-privilege-escalation-in-windows-environment)
5. [Threat-Hunting-Cheat-Sheat](https://github.com/allan9595/Threat-Hunting-Cheat-Sheat/blob/master/threat-hunting-cheat-sheet.md)
6. [Hunting for Apache rootkit using OSquery](https://www.defensive-security.com/resources/hunting-for-apache-rootkit-using-osquery)
7. [APT Hunter Windows Event Logs](https://shells.systems/introducing-apt-hunter-threat-hunting-tool-via-windows-event-log/)
8. [Kestrel TH Language](https://kestrel.readthedocs.io/en/latest/)
9. [Hunting NGROK](https://c99.sh/hunting-ngrok-activity/)
10. [Translation Engine for Threat Hunters](https://uncoder.io/)

**Log Management/SOC**
1. [Windows Powershell Logging Cheat Sheet](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5ba3dc87e79c703f9bfff29a/1537465479833/Windows+PowerShell+Logging+Cheat+Sheet+ver+Sept+2018+v2.2.pdf)
2. [https://cyberstartupobservatory.com/cyber-security-frameworks/](https://correlatedsecurity.com/soar-critical-success-factors/amp/?__twitter_impression=true)
3. [Automate the boring for your SOC with automatic investigation and remediation!](https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/automate-the-boring-for-your-soc-with-automatic-investigation/ba-p/1381038)

**Digital Forensic and Incident Response (DFIR)**
1. [Banking Trojan](https://articles.forensicfocus.com/2019/05/06/following-the-rtm-forensic-examination-of-a-computer-infected-with-a-banking-trojan/)
2. [DFIR Cheat Sheet](https://www.jaiminton.com/cheatsheet/DFIR/)
3. [Volatility Workbench](https://www.osforensics.com/tools/volatility-workbench.html)
4. [Incident Handling Automation Project](https://github.com/certtools/intelmq)
5. [Excel Pivot Functions Forensic Analysis Techniques](https://www.mandiant.com/resources/blog/excelerating-analysis-lookup-pivot)
6. [RE&CT Framework](https://atc-project.github.io/atc-react/)
7. [Velociraptor is an advanced digital forensic and incident response tool that enhances your visibility into your endpoints.](https://docs.velociraptor.app/)
8. [Sysmon 11 — DNS improvements and FileDelete events](https://medium.com/falconforce/sysmon-11-dns-improvements-and-filedelete-events-7a74f17ca842)
9. [GRR Rapid Response](https://github.com/google/grr)
10. [Writing Reports](https://joshbrunty.github.io/2021/01/27/reporting.html)
11. [Collecting And Analyzing Logs In Azure AD](https://m365internals.com/2021/03/08/incident-response-series-collecting-and-analyzing-logs-in-azure-ad/)
12. [Latest File Extension used by Hackers](https://filesec.io/)
13. [Windows Common Techniques used by Malware](https://malapi.io/)
14. [Finding the Evil in TLS 1.2 Traffic – Detecting Malware on Encrypted Traffic](https://www.socinvestigation.com/finding-the-evil-in-tls-1-2-traffic-detecting-malware-on-encrypted-traffic/)
15. [Most Common Windows Event IDs to Hunt – Mind Map](https://www.socinvestigation.com/most-common-windows-event-ids-to-hunt-mind-map/)
16. [No Logs? No Problem!](https://labs.jumpsec.com/no-logs-no-problem-incident-response-without-windows-event-logs/)

**Scripting**
1. [Lazy Script Kali Linux](https://hakin9.org/the-lazy-script-will-make-your-life-easier-and-of-course-faster/)
2. [OSINT-Probe Spider](https://github.com/Aravindha1234u/Probe_spider)
3. [ADFS Spray&Brute](https://github.com/ricardojoserf/adfsbrute)

**CyberSecurity Framework**
1. [NIST](https://www.praxiom.com/nist.htm)
2. [Cyber Security Frameworks – Infographics](https://cyberstartupobservatory.com/cyber-security-frameworks/)

**Misc**
1. [Moloch Full Packet Capture](https://molo.ch/)
2. [An OODA-driven SOC Strategy using: SIEM, SOAR and EDR](https://correlatedsecurity.com/an-ooda-driven-soc-strategy-using-siem-soar-edr/)
3. [SOC Automated Workflow](https://github.com/TheresAFewConors/Sooty)

**TO BE UPDATED FROM TIME TO TIME**

**IF YOU WISH TO CONTRIBUTE TO THIS REPO, PLEASE SEND EMAIL TO ikbal@rawsec.com OR VIA TELEGRAM: @Viszsec**