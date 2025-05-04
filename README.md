# 🔴 JKZH Red Team Cloud Lab Project (DVWA Phase 1)

## 📌 Overview

This project documented my hands-on experience building and attacking a cloud-based Red Team lab using Vultr, Kali Linux, and Ubuntu Server. I deployed the Damn Vulnerable Web App (DVWA), conducted both manual and automated attacks using tools like Nmap, Burp Suite, OWASP ZAP, and Metasploit, and practiced responsible, real-world offensive security techniques in a legally owned environment.

---

## 🎯 Objectives

- Deployed fresh attacker and victim machines using Vultr
- Configured and secured DVWA in a Linux LAMP stack
- Performed enumeration, exploitation, and traffic interception
- Practiced ethical hacking techniques using industry tools
- Captured results for documentation and reporting

---

## 🛠️ Tools & Services

| Tool/Service       | Purpose                                             |
|--------------------|-----------------------------------------------------|
| Vultr              | VPS cloud hosting provider                          |
| Kali Linux         | Attacker box with penetration testing tools         |
| Ubuntu 25.04       | Victim box running Apache2, MySQL, PHP, and DVWA    |
| DVWA               | Target application for ethical exploitation         |
| Nmap               | Reconnaissance and port scanning                    |
| OWASP ZAP          | Authenticated DAST scanning                         |
| Burp Suite         | Traffic interception and request manipulation       |
| Metasploit         | Exploitation framework (future phase)               |
| PowerShell / SSH   | Remote access from my Windows machine               |

---

## 🧪 Lab Setup Walkthrough

### ✅ Step 1: Provisioned Vultr VMs

I deployed 2 VPS instances:

- Kali Linux (Attacker): `2 vCPUs, 4GB RAM, 80 GB SSD`  
  _Public IP: 104.238.128.7_

- Ubuntu 25.04 (Victim): `1 vCPU, 2GB RAM, 80 GB SSD`  
  _Public IP: 208.167.237.7_

---

### ✅ Step 2: Configured Firewall with UFW (Ubuntu Victim)

I ran the following commands to secure access to the victim server:

```bash
apt update && apt install ufw -y
ufw allow from 104.238.128.7 to any port 22 proto tcp
ufw allow from 104.238.128.7 to any port 80 proto tcp
ufw allow from 104.238.128.7 to any port 3000 proto tcp
ufw enable
```

---

### ✅ Step 3: Installed Apache, MySQL, PHP (LAMP Stack)

I installed the necessary LAMP stack components:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install apache2 php libapache2-mod-php php-mysql mysql-server git unzip -y
```

---

### ✅ Step 4: Installed & Configured DVWA

From my **local Windows machine**, I opened PowerShell and connected to the Ubuntu server via SSH:

```powershell
ssh root@208.167.237.7
```

Once I was connected, I ran the following commands on the Ubuntu victim server to clone and prepare DVWA for configuration:

```bash
# Navigated to the Apache web root
cd /var/www/html
# Cloned the DVWA repository from GitHub
sudo git clone https://github.com/digininja/DVWA.git
# Set the correct ownership so Apache could read/write
sudo chown -R www-data:www-data DVWA
# Adjusted permissions for execution and access
sudo chmod -R 755 DVWA

# Moved into the configuration directory
cd DVWA/config
# Copied the sample config to an active config file
sudo cp config.inc.php.dist config.inc.php
# Edited database settings inside the configuration file
sudo nano config.inc.php
```

I updated the config file with the following:

```php
$_DVWA['db_user'] = 'root';
$_DVWA['db_password'] = '';
```

Next, I created the database:

```bash
sudo mysql -u root
```

Inside MySQL:

```sql
CREATE DATABASE dvwa;
ALTER USER 'root'@'localhost' IDENTIFIED BY '';
FLUSH PRIVILEGES;
EXIT;
```

Then I enabled modules and restarted Apache:

```bash
sudo a2enmod rewrite
sudo systemctl restart apache2
```

Finally, I initialized DVWA via browser:  
`http://208.167.237.7/DVWA/setup.php`

---

### ✅ Step 5: Configured the Kali Attacker Machine

I SSH'd into the Kali machine from my Windows PC and updated the system:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install metasploit-framework zaproxy -y
```

Then I verified the installations by running:

```bash
msfconsole
zap
nmap --version
```

---

### ✅ Step 6: Scanned the Target with Nmap

I performed reconnaissance scans against the victim:

```bash
nmap -A -T4 208.167.237.7
nmap --script vuln 208.167.237.7
```

---

### ✅ Step 7: Performed Manual SQL Injection

- I visited: `http://208.167.237.7/DVWA`
- I logged in using the default credentials: `admin / password`
- I navigated to the **SQL Injection** module
- I changed the security settings from Low → High
- I tested the classic payload:

```sql
1' OR 1=1 --
```

---

### ✅ Step 8: Ran an Authenticated OWASP ZAP Scan

1. I opened ZAP and launched the built-in browser.
2. I logged into DVWA using: `admin / password`.
3. I captured the session cookies and defined the scan context.
4. I marked input fields as parameters.
5. I ran a full **Active Scan**.

📊 **Results:**
- 3,600+ requests sent
- 200+ vulnerabilities found (SQLi, XSS, missing headers)

📁 Saved Report:  


---

### ✅ Step 9: Used Burp Suite to Intercept Traffic

- I set Firefox's proxy to: `127.0.0.1:8080`
- I intercepted HTTP POST login requests
- I used Burp Repeater to resend and manipulate payloads
- I observed and documented DVWA’s responses

---

### ✅ Step 10: Troubleshooting Summary

| Issue                  | Resolution                                  |
|------------------------|----------------------------------------------|
| PHP 500 Errors         | I installed missing PHP modules             |
| MySQL Access Denied    | I updated the root auth method              |
| SSH Root Login Blocked | I edited `/etc/ssh/sshd_config`             |
| Apache Errors          | I restarted Apache2 and MySQL services      |

---

## 📸 Captured Evidence

- Screenshots: SQLi results, ZAP findings, Burp Repeater payloads
- HTML scan report (ZAP)
- Terminal logs from setup and scans

![Screenshot 2025-05-03 120918](https://github.com/user-attachments/assets/b75a61a9-5288-4618-94c3-ae0715bf6649)
![Screenshot 2025-05-03 120944](https://github.com/user-attachments/assets/b50ade6a-d733-4c0d-8f22-501d47e314f9)
![Screenshot 2025-05-03 122049](https://github.com/user-attachments/assets/9cc5d055-b5b1-462d-93f7-e681ed0d078a)
![Screenshot 2025-05-03 165442](https://github.com/user-attachments/assets/762b9593-9cd1-46f3-943f-ee98a57f7448)
![Screenshot 2025-05-03 170131](https://github.com/user-attachments/assets/e3b83589-bff7-4f03-9345-1460aa108983)
![Screenshot 2025-05-03 170325](https://github.com/user-attachments/assets/f83706ee-c963-4d54-97b1-1262a8ec293c)
![Screenshot 2025-05-03 170434](https://github.com/user-attachments/assets/7faa1337-980a-4086-8c6c-af937e0547b5)
![Screenshot 2025-05-03 170540](https://github.com/user-attachments/assets/d15c21d7-1098-41af-b3c7-38c138d1f40c)
![Screenshot 2025-05-03 170607](https://github.com/user-attachments/assets/be88b05d-2d63-4501-a911-03ed84b720bf)
![Screenshot 2025-05-03 175001](https://github.com/user-attachments/assets/ff17d412-99b6-401d-80f8-aeeb180ce76d)
![Screenshot 2025-05-03 175235](https://github.com/user-attachments/assets/78e34534-dfc3-4443-8637-57c575365116)
![Screenshot 2025-05-03 175444](https://github.com/user-attachments/assets/49c70bda-a2c9-42d6-ad99-aa3cf79ae129)
![Screenshot 2025-05-03 180239](https://github.com/user-attachments/assets/a9aa0b1b-a5ea-46de-a33a-dd8e05cb4209)
![Screenshot 2025-05-03 180557](https://github.com/user-attachments/assets/56587ec8-cb82-406c-afbd-e77ff581f671)
![Screenshot 2025-05-03 180644](https://github.com/user-attachments/assets/42a33e26-7c45-4808-bb34-f1a883b5bdc4)
![Screenshot 2025-05-03 180802](https://github.com/user-attachments/assets/c57de93e-9522-49f6-ac86-576f2e3795dc)
![Screenshot 2025-05-03 180933](https://github.com/user-attachments/assets/7eef1e75-9c1a-4e0b-a40e-41c9c600fee5)
![Screenshot 2025-05-03 181042](https://github.com/user-attachments/assets/8eede5d6-7a6c-4913-b8bc-dbd5c8a2ecfe)
![Screenshot 2025-05-03 181133](https://github.com/user-attachments/assets/e8e5bab5-e267-48fa-96a1-32e19b015f49)
![Screenshot 2025-05-03 181425](https://github.com/user-attachments/assets/f0a530b0-797b-4c7a-bbfa-c1929ad4beea)
![Screenshot 2025-05-03 181433](https://github.com/user-attachments/assets/074f006c-d53d-4bbd-8817-9595cc433d71)
![Screenshot 2025-05-03 181546](https://github.com/user-attachments/assets/f9531a83-a8df-4bb0-ab37-077e09fa95e5)
![Screenshot 2025-05-04 160537](https://github.com/user-attachments/assets/6dcb05eb-bf50-4cbb-8300-9977791231eb)
![Screenshot 2025-05-03 182515](https://github.com/user-attachments/assets/585b71ba-4b69-427c-aeb9-f8a146397021)
![Screenshot 2025-05-03 182633](https://github.com/user-attachments/assets/b2258bb6-14ca-4f5c-bcdc-38a03d661d71)
![Screenshot 2025-05-03 182843](https://github.com/user-attachments/assets/5ff0f9c1-18cc-4762-bec4-8256e17227bb)
![Screenshot 2025-05-03 182950](https://github.com/user-attachments/assets/b27048b9-58f4-43e9-b03c-6a754c32b4d8)
![Screenshot 2025-05-03 183115](https://github.com/user-attachments/assets/70b03dad-368c-4fb7-b404-1e6c6be8f6bd)
![Screenshot 2025-05-03 185124](https://github.com/user-attachments/assets/76efbd6a-2b3b-4d0b-80af-0958572c8102)
![Screenshot 2025-05-03 185153](https://github.com/user-attachments/assets/ba2c2c66-0d57-489b-88fc-1254d09a0957)
![Screenshot 2025-05-03 185216](https://github.com/user-attachments/assets/0b95bbe4-7bd0-4fd2-a34c-48712031d69f)
![Screenshot 2025-05-03 185624](https://github.com/user-attachments/assets/24caf620-9d3d-4139-b804-a24a698c17ff)
![Screenshot 2025-05-03 185704](https://github.com/user-attachments/assets/6ce984ae-e107-41d0-8482-4e7baed437b5)
![Screenshot 2025-05-03 185727](https://github.com/user-attachments/assets/f8ba23f3-433c-4913-a5dc-d02f19262e56)
![Screenshot 2025-05-03 185806](https://github.com/user-attachments/assets/d0eafc32-ff0a-410d-882b-2cc423bfcb84)

---

## 🚧 Potential Next Steps

- [ ] Deploy OWASP Juice Shop using Docker
- [ ] Use Metasploit for deeper exploitation (reverse shells)
- [ ] Expand documentation and produce professional reports

---

## 🧾 Legal & Ethical Statement

This lab was created and operated 100% ethically. I provisioned all systems, and I did not scan or exploit any external or unauthorized targets. I used all tools solely for educational and professional development purposes.

---

## 🙏 Thanks for Following Along

I appreciate you taking the time to review this project.

— **Jonathan (https://github.com/JKZH-Cyber)**

