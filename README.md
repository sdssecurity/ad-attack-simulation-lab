# AD Lab: Enterprise Active Directory Compromise & SOC Detection Simulation

![Lab Topology](https://img.shields.io/badge/Security-Red%20%2F%20Blue%20Team-blue.svg)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Adversary%20Emulation-orange.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20Server%202022%20%7C%20Kali%20Linux-lightgrey.svg)

An end-to-end adversary emulation and Blue Team detection engineering project simulating an Advanced Persistent Threat (APT) lifecycle within a custom Windows Active Directory lab environment (`corp.local`). This project maps offensive Red Team tactics to high-fidelity endpoint telemetry (Windows Security Events, Sysmon, OpenSSH logs) to build actionable SOC detection rules and infrastructure hardening strategies.

---

## 🏗️ Lab Architecture & Topology

The environment models a segmented enterprise network hosting a Kali Linux attacker node, a standard member workstation, and an Active Directory Domain Controller.

| Hostname | Role | IP Address | Operating System |
| :--- | :--- | :--- | :--- |
| **Kali Linux** | Attacker / C2 Infrastructure | `192.168.56.102` | Kali Linux (Rolling) |
| **WS-01** (`ws01.corp.local`) | Workstation / Initial Foothold | `192.168.56.130` | Windows 10 / Server 2022 |
| **DC-01** (`dc01.corp.local`) | Domain Controller / Tier 0 | `192.168.56.110` | Windows Server 2022 |

```text
  +------------------+         LLMNR Poisoning & Evil-WinRM         +----------------------+
  |    Kali Linux    | -------------------------------------------> | WS-01 (Workstation)  |
  |  192.168.56.102  | <------------------------------------------- |    192.168.56.130    |
  +------------------+                                              +----------------------+
           |                                                                    |
           |                  SSH over Port 22 (Password Reuse)                 |
           +--------------------------------------------------------------------> v
                                                                    +----------------------+
                                                                    | DC-01 (Domain Cont.) |
                                                                    |    192.168.56.110    |
                                                                    +----------------------+
```

---

## ⚔️ Attack Lifecycle & MITRE ATT&CK Matrix

| # | Attack Phase | Adversary TTP & Tool (Red Team) | MITRE ID | Telemetry & Blue Team Detection | Target Host |
|---|---|---|---|---|---|
| **1** | **Reconnaissance** | Nmap Aggressive Port Scan | `T1595` | IDS/IPS / Netflow Traffic Analysis | WS-01, DC-01 |
| **2** | **Initial Access** | Responder (LLMNR) + Hashcat + Evil-WinRM (`j.doe`) | `T1557` / `T1021` | WinEvent ID **4624 & 4769**: Network Logon (Type 3) from Kali IP & TGS Request | WS-01 |
| **3** | **Privilege Escalation** | Impacket-GetNPUsers (AS-REP Roasting) + Evil-WinRM (`svc_sql`) | `T1558` / `T1021` | WinEvent ID **91 & 4672**: WSMan shell creation & Assigned Special Privileges | WS-01 |
| **4** | **Credential Harvesting** | Local SAM Extraction & Credential Manager Enumeration | `T1003` / `T1087` | WinEvent ID **5379**: Anomalous read operation on local Credential Manager | WS-01 |
| **5** | **AD Enumeration** | NetExec (`nxc ldap`) & PowerShell Active Directory Queries | `T1087` | Sysmon Event ID **3**: PowerShell querying Domain Controller LDAP ports | DC-01 |
| **6** | **Lateral Movement** | SSH Access via Compromised Administrator Account (Password Reuse) | `T1021` | OpenSSH Event ID **4** / WinEvent ID **4624**: Accepted SSH password auth from Kali IP | DC-01 |
| **7** | **Credential Access** | Living-off-the-Land (LotL): LSASS Memory Dump (`rundll32.exe comsvcs.dll`) | `T1003` | Sysmon Event ID **1**: `rundll32.exe` execution calling `Minidump` for `lsass.dmp` | DC-01 |
| **8** | **Domain Takeover** | Impacket-Secretsdump (DCSync) & Mimikatz (Golden Ticket Forgery) | `T1003` / `T1558` | WinEvent ID **4662**: Domain replication (`Directory Service Access`) requested anomalously | DC-01 |
| **9** | **Exfiltration & C2** | Encrypted Command Channel & Data Exfiltration via SSH (Port 22) | `T1048` | Sysmon Event ID **3**: SSH connection over Port 22 linking `Administrator` to Kali | DC-01 |

---

## 🔍 Key Artifacts & Detection Engineering

### 1. Initial Access & LLMNR Poisoning (`j.doe`)
* **Offensive Action:** Responder intercepted broadcast queries on the local subnet, capturing NTLMv2 hashes. Hashcat cracked `j.doe`'s password, and Evil-WinRM established a remote shell on `WS-01`.
* **SOC Detection:** 
  * Windows Security Event ID **4624** (Logon Type 3) logged the inbound network authentication from Kali (`192.168.56.102`) to `WS-01`.

### 2. Privilege Escalation via AS-REP Roasting & Misconfigurations (`svc_sql`)
* **Offensive Action:** The `svc_sql` account had the "Do not require Kerberos pre-authentication" flag enabled. Impacket extracted its AS-REP hash, which was cracked offline. Furthermore, `svc_sql` was incorrectly assigned Local Administrator rights on `WS-01` and Backup Operator privileges on `DC-01`.
* **SOC Detection:**
  * Windows Security Event ID **4672** captured special privileges assigned to a new logon (`SeBackupPrivilege`, `SeRestorePrivilege`).
  * Microsoft-Windows-Windows Remote Management Operational Event ID **91** tracked the WSMan shell creation for `CORP\svc_sql`.

### 3. Living-off-the-Land Credential Theft (`rundll32`)
* **Offensive Action:** To bypass strict antivirus signatures, the adversary used legitimate Windows binaries to dump LSASS memory:
  ```powershell
  rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 652 C:\Windows\Temp\lsass.dmp full
  ```
* **SOC Detection:**
  * Sysmon Event ID **1** (Process Creation) flagged `rundll32.exe` referencing `comsvcs.dll` and `MiniDump` strings.

### 4. Domain Takeover & DCSync (`Administrator`)
* **Offensive Action:** Leveraging password reuse between `svc_sql` and the Domain Administrator account, Impacket's `secretsdump` performed a DCSync attack against `DC-01` to pull the `krbtgt` hash.
* **SOC Detection:**
  * Windows Security Event ID **4662** ("An operation was performed on an object") detected Domain Controller replication rights (`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`) requested by the `Administrator` account.

---

## 🛡️ Infrastructure Remediation & Hardening Strategies

To eliminate the systemic vulnerabilities exploited during this engagement, implement the following defense-in-depth measures:

1. **Privileged Access Management (PAM):**
   * **Strip Unauthorized Memberships:** Immediately remove service accounts like `svc_sql` from high-privilege groups such as `Backup Operators` and local `Administrators`.
   * **Deploy Microsoft LAPS:** Enforce Local Administrator Password Solution across all workstations to prevent lateral pass-the-hash attacks.

2. **Identity Security & Password Hygiene:**
   * **Enforce Active Directory Tiering:** Restrict Tier 0 accounts (`Domain Admins`) from authenticating to Tier 2 workstations.
   * **Migrate to gMSAs:** Replace standard user accounts running database or application services with **Group Managed Service Accounts** to automate 120-character password rotation.

3. **Active Directory Protocol Hardening:**
   * **Mandate Kerberos Pre-Authentication:** Audit and disable the "Do not require Kerberos pre-authentication" setting across all user and service accounts.
   * **Disable LLMNR / NBT-NS:** Explicitly disable Link-Local Multicast Name Resolution via Group Policy to prevent broadcast poisoning and Responder attacks.

4. **Endpoint Defense & LSASS Isolation:**
   * **Enable LSA Protection & Credential Guard:** Configure `RunAsPPL` (Protected Process Light) via registry/GPO to isolate LSASS memory space and block memory scraping tools (Mimikatz, `comsvcs.dll`).
