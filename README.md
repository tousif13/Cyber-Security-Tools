# Cyber-Security-Tools
Overview of some of the Cyber Security tools in Kali Linux.

# Nmap ![image](https://user-images.githubusercontent.com/33444140/224762090-0ec347c7-f56f-4780-a9b6-9877b380b0ff.png)
- Nmap known as Network Mapper is a tool used for network scanning and security auditing
- It is used to detect vulnerabilities , discover open ports and services.
- Helps to identify services like DNS servers , web servers that are running on a system.
- Determine what type of OS , packet filters are in use.
- It provides information on port type , its state , services running and its version.

# Spiderfoot ![image](https://user-images.githubusercontent.com/33444140/224767455-ba39ecf8-cf5e-402a-8b8b-ae4b23e8d977.png)
- Spiderfoot is an open source intelligence (OSINT) automation tool for intelligence gathering (footprinting).
- Used to gather info of given target such as IP address , hostname , domain name.
- To identify what information is openly exposed and any malicious IPs.
- Tool can be used as both offensive and defensive as per the pentester.
- Useful for threat intelligence and digital investigations.

# Legion ![image](https://user-images.githubusercontent.com/33444140/224770726-517fecae-19e6-4a95-bc86-1b6dee83a807.png)
- Legion tool is a semi automated network penetration testing tool.
- Automatically detects CVEs (Common Vulnerabilities and Exposures).
- Realtime autosaving of project results and tasks.
- Automatic recon and scanning with auto-scheduled scripts.
- Allow pentesters to quickly exploit attack vectors on hosts.

# Ike-scan ![image](https://user-images.githubusercontent.com/33444140/224778683-0bb5d6ba-9ca5-4855-b8ed-de428d145910.png)
- IKE(Internet Key Exchange) Scan is used to discover and fingerprints IKE hosts.
- Used by IPsec and vast majority of IPsec VPNs use IKE for key exchange.
- Uses retransmission backoff pattern.
- IKE scan sends request and displays the responded hosts as a part of host discovery.
- It does Fingerprinting which determines implementation used by IKE hosts.

# Nikto ![image](https://user-images.githubusercontent.com/33444140/224781722-8ccb27ec-ff6b-4687-8f3a-b0adbcd16b1f.png)
- Nikto is an open-source software used to scan web-server vulnerabilities.
- It performs comprehensive tests against web servers for multiple security threats.
- Supports full HTTP Proxy and finds sub-domain.
- Checks for version related problems and outdated web servers.
- Finds common vulnerabilities and reports unusual headers.

# Unix-privesc-check ![image](https://user-images.githubusercontent.com/33444140/224784140-71e34430-91e0-4035-9c7d-c5bf9b04c8c7.png)
- Unix-privesc-check is a vulnerability analysis tool that runs on Unix systems.
- It finds misconfigurations that escalate privileges by unprivileged users. 
- Used for Security patching and IP stack configuration.
- It can even be run as a cron job to check the misconfigurations.
- Checks weak file permissions and configuration of local applications.

# Burpsuite ![image](https://user-images.githubusercontent.com/33444140/225063866-655b22ab-b3ed-4d4f-bf04-8fbac4d01ab9.png)
- Burpsuite is an integrated platform for performing security testing of web applications.
- Finds and exploits security vulnerabilities.
- Initial mapping and analysis of attack surface.
- Combines advanced manual techniques with state-of-the-art automation.
- Contains intercepting proxy that lets users see and modify requests and responses.

# Sqlmap ![image](https://user-images.githubusercontent.com/33444140/225064309-4294e62f-23b8-4bcd-8632-0123a627474a.png)
- Sqlmap detects and exploits SQL injection vulnerabilities in web applications.
- DBMS fingerprinting and retrieving DBMS session user and database.
- Enumerate users, password hashes, privileges, roles, tables and columns.
- Supports dumping database tables and searches for specific database names and columns.
- Supports executing arbitrary commands and retrieving their standard output.

# Wpscan ![image](https://user-images.githubusercontent.com/33444140/225068242-277c4cc9-8582-48c6-941a-cfa8ec0bf843.png)
- Wpscan scans a target WordPress and enumerates any plugins.
- Finds what plugins are installed and any associated vulnerabilities.
- Finds database dumps that may be publicly accessible.
- Finds publicly accessible and exposed files and error logs.

# John the Ripper ![image](https://user-images.githubusercontent.com/33444140/225069872-88a50471-1246-4d12-af4e-30ff53a76512.png)
- John the Ripper is a password security auditing and password recovery tool.
- Supports hundreds of hash and cipher types.
- Reveals weak passwords and performs brute-force attacks.
- Uses sessions to remember previous results and detect hash types automatically.
- Particularly efficient when combined with open-source wordlists.

# Ncrack ![image](https://user-images.githubusercontent.com/33444140/225075617-fe61ceeb-4d2b-4e9b-90ba-88f91f397d6d.png)
- ncrack is a network authentication cracking tool.
- Secure the networks by proactively testing all the hosts and networking devices.
- Granting the user full control of network operations.
- Supports many protocols such as SSH, RDP, FTP, Telnet, http(s), etc.
- Allows for rapid and reliable large-scale auditing of multiple hosts.

# Hashcat ![image](https://user-images.githubusercontent.com/33444140/225076026-77cb5857-2b6a-4477-a4ce-9b1a322c05a1.png)
- Hashcat is a password cracker and recovery utility.
- Supports various hashing algorithms such as MD5, SHA1, NTLM etc.
- Hashcat offers various attack modes such as Dictionary, Mask, Table-Lookup attacks.
- Distributed cracking networks can be supported using overlays.
- Supports both hex-charset and hex-salt files.

# Aircrack-ng ![image](https://user-images.githubusercontent.com/33444140/225078588-0ccf0f82-ec1e-4707-82d5-b10d81760f1e.png)
- Aircrack-ng is a complete suite of tools to assess WiFi network security.
- Monitors packet capture and export of data to text files.
- Checks WiFi cards and driver capabilities.
- Replay attacks, fake access points, deauthentication via packet injection.
- WEP and WPA PSK cracking.

# Kismet ![image](https://user-images.githubusercontent.com/33444140/225081421-744fe419-c50d-4b45-aeef-3a0c5283b405.png)
- Kismet is a wireless network and device detector, sniffer, and wardriving tool.
- It is also a WIDS(Wireless Intrusion Detection) framework.
- Works with WiFi interfaces, Bluetooth interfaces, and some SDR(Software Defined Radio) hardware.
- A bigger range of configurations and drivers is available.

# Clang ![image](https://user-images.githubusercontent.com/33444140/225094727-edb83943-9e99-4509-ab67-5953b1f4cd82.png)
- Clang tool is a front end compiler to compile C and C++ langs into machine code.
- Used for parsing source code.
- Optimizes the Abstract Syntax Tree(AST).
- Fast syntax checking, automatic formatting, refactoring, etc.

# NASM shell ![image](https://user-images.githubusercontent.com/33444140/225095776-dd6f86e8-5b93-4c56-8f82-718f12c51429.png)
- NASM known as Netwide Assembler will output flat-form binary files.
- Outputs object files, COFF and ELF Unix object files, Win32 object files.
- Includes NDISASM, a prototype x86 binary-file disassembler.
- Assembles a flat binary without needing the complication of a linker.

# Metasploit Framework ![image](https://user-images.githubusercontent.com/33444140/225097771-961338fd-0721-4584-afeb-9b0b0a088b39.png)
- Metasploit Framework is an open-source penetrating framework to create security tools and exploits.
- Supports vulnerability research, exploit development and creation of custom security tools.
- Helps users to proactively mend weaknesses before exploitation by hackers.
- Set payload command allows easy, quick access to switch payloads.
- Metasploit able to exit the target system cleanly without being detected.

# Social Engineering Toolkit ![image](https://user-images.githubusercontent.com/33444140/225208808-d1ed4e7f-b6f5-459f-8192-593246970b68.png)
- Social Engineer Toolkit(SET) is a tool aimed at penetration testing around social engineering.
- SET has a no of custom attack vectors to make a believable attack.
- Supports integration with third-party modules.
- Allows multiple tweaks from the configuration menu.
- SET offers multiple attack options such as Website Attacks, QRCode Attacks, Mass Mailing, Spear-Phishing, etc.

# Dnschef ![image](https://user-images.githubusercontent.com/33444140/225209970-953fffa8-970d-49d7-84d7-edb990caeeb2.png)
- DNSChef is a DNS proxy for Penetration Testers and Malware Analysts.
- DNS proxy is used for application network traffic analysis among other users.
- DNSChef is capable of forging responses based on inclusive and exclusive domain lists.
- DNSChef will point queries to your proxy/server host with properly configured services.

#Netsniff-ng ![image](https://user-images.githubusercontent.com/33444140/225211458-9c9ff9ae-d016-4c98-936f-66250826f2f0.png)
- netsniff-ng is a high performance network sniffer for packet inspection.
- Used for protocol analysis, reverse engineering or network debugging.
- The gain of performance is reached by 'zero-copy' mechanisms so that no need to copy packets from kernel space to user space.
- netsniff-ng also supports early packet filtering in the kernel.
- netsniff-ng can capture different pcap formats and also supports analysis, replaying and dumping of raw 802.11 frames.

#mitmproxy ![image](https://user-images.githubusercontent.com/33444140/225213344-81c94a34-ad8f-4dc9-a5dd-dc9d4264b930.png)
- mitmproxy is an interactive man-in-the-middle proxy for HTTP and HTTPS.
- Intercept and modify HTTP and HTTPS requests and responses.
- Provides a console interface that allows traffic flows to be inspected and edited.
- Supports Reverse and transparent proxy modes.
- SSL/TLS certificates for interception are generated on the fly.

#Sslsplit ![image](https://user-images.githubusercontent.com/33444140/225221344-80e5be17-cd3d-46e7-b84c-c870f41234cf.png)
- SSLsplit is a tool for MIM attacks against SSL/TLS encrypted network connections.
- Connections are transparently intercepted through a network address translation engine and redirected to SSLsplit.
- Dynamically generates a certificate and signs it with private key of CA certificate.
- Useful for network forensics and penetration testing.

# Mimikatz ![image](https://user-images.githubusercontent.com/33444140/225222552-c7560ea0-b8ed-4da4-a2a7-d857d1fb87a1.png)
- Mimikatz is an open-source application that allows users to view and save authentication credentials.
- It uses admin rights on Windows to display passwords of currently logged in users.
- Attackers commonly use Mimikatz to steal credentials and escalate privileges.
- Provides functionality for a user to pass a Kerberos ticket to another computer.
- Passes a unique key obtained from a domain controller to impersonate a user.

