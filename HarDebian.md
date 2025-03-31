# Hardening
test
## I. Hardening HTTP : TLS with Cerbot

```BASH
sudo apt -y install python3-certbot-apache
```

```BASH
sudo certbot --apache -d site.fqdn.tld
```
## II. Hardening SSH

- Make a copy before tout péter
```BASH
sudo mv /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
```

- Modification du ficihier de configuration
```BASH
sudo vim /etc/ssh/sshd_config
```

- Useful command to troubleshoot SSH
```BASH
ssh -vvv user@site.fqdn.tld
```

## III. Hardening Apache2

- Mise en place des headers
```BASH
sudo a2enmod headers
```
- Then use the `security.conf` 

## IV. Fail2ban

### Installing

- Need to install rsylog first (fail2ban will need it)
```BASH
sudo apt -y install fail2ban
```

- Enable and check the service
```BASH
sudo systemctl enable fail2ban && \
sudo systemctl status fail2ban -l --no-pager
```

### SSHD

- Use our favorite configuration for sshd
```BASH
sudo bash -c 'cat <<EOF > /etc/fail2ban/jail.d/sshd.conf
[sshd]
enabled  = true
port     = 22
logpath  = %(sshd_log)s
backend  = %(sshd_backend)s
maxretry = 3
bantime  = 3700
findtime = 3600
ignoreip = 91.170.181.39
EOF'
```

### Apache2

- Use our favorite configuration for Apache2
```BASH
sudo bash -c 'cat <<EOF > /etc/fail2ban/jail.d/apache.conf
# Protects against authentication failures (e.g., .htpasswd brute-force attacks)
[apache-auth]
enabled  = true
port     = http,https
filter   = apache-auth
logpath  = /var/log/apache2/*error.log
maxretry = 5
findtime = 3600
bantime  = 86400

# Blocks known malicious bots (e.g., sqlmap, nikto, masscan, etc.)
[apache-badbots]
enabled  = true
port     = http,https
filter   = apache-badbots
logpath  = /var/log/apache2/*access.log
maxretry = 3
findtime = 3600
bantime  = 86400

# Blocks scanners searching for sensitive files (phpMyAdmin, wp-login, etc.)
[apache-botsearch]
enabled  = true
port     = http,https
filter   = apache-botsearch
logpath  = /var/log/apache2/*access.log
maxretry = 3
findtime = 3600
bantime  = 86400

# Blocks fake GoogleBots pretending to be real crawlers
[apache-fakegooglebot]
enabled  = true
port     = http,https
filter   = apache-fakegooglebot
logpath  = /var/log/apache2/*access.log
maxretry = 2
findtime = 3600
bantime  = 86400

# Protects against access to non-existent or suspicious files (ASP, JSP, CGI, EXE…)
[apache-noscript]
enabled  = true
port     = http,https
filter   = apache-noscript
logpath  = /var/log/apache2/*access.log
maxretry = 5
findtime = 3600
bantime  = 86400

# Blocks scans for user directories (e.g., /~admin/)
[apache-nohome]
enabled  = true
port     = http,https
filter   = apache-nohome
logpath  = /var/log/apache2/*access.log
maxretry = 3
findtime = 3600
bantime  = 86400

# Blocks potential exploit attempts (e.g., malformed 400 HTTP requests)
[apache-overflows]
enabled  = true
port     = http,https
filter   = apache-overflows
logpath  = /var/log/apache2/*error.log
maxretry = 3
findtime = 3600
bantime  = 86400

# Protects against access to password files (passwd, password.txt, etc.)
[apache-pass]
enabled  = true
port     = http,https
filter   = apache-pass
logpath  = /var/log/apache2/*access.log
maxretry = 2
findtime = 3600
bantime  = 86400

# Blocks Shellshock attack attempts (exploits CGI vulnerabilities)
[apache-shellshock]
enabled  = true
port     = http,https
filter   = apache-shellshock
logpath  = /var/log/apache2/*access.log
maxretry = 1
findtime = 3600
bantime  = 86400

# Blocks SQL Injections attack attempts
[apache-sqli]
enabled  = true
port     = http,https
filter   = apache-sqli
logpath  = /var/log/apache2/*access.log
maxretry = 3
findtime = 3600
bantime  = 86400

# Blocks DOS attacks
[apache-dos]
enabled  = true
port     = http,https
filter   = apache-dos
logpath  = /var/log/apache2/access.log
maxretry = 100
findtime = 10
bantime  = 3600

# No Nikto 
[apache-no-hacking]
enbaled  = true
port     = http,https
filter   = apache-nohacking
logpath  = /var/log/apache2/*access_log
maxretry = 1

# No OS Injection
[apache-os-injection]
enabled  = true
port     = http,https
filter   = apache-osinjection
logpath  = /var/log/apache2/*access.log
maxretry = 1
EOF'
```

- Filter for SQLi
```BASH
sudo bash -c 'cat > /etc/fail2ban/filter.d/apache-sqli.conf <<EOF
[Definition]
failregex = ^<HOST> .* "(GET|POST) .*(%%27|'"'"'|%%20or%%20|%%20and%%20|union.*select|select.*from|insert.*into|update.*set|delete.*from).* HTTP.*"
ignoreregex =
EOF'
```

- Filter for Apache DOS
```BASH
sudo bash -c 'cat > /etc/fail2ban/filter.d/apache-dos.conf <<EOF
[Definition]
failregex = ^<HOST> -.*"(GET|POST).* HTTP.*$
ignoreregex =
EOF'
```
- Filter for OS injection
```BASH
# Fail2Ban configuration file
#
# Blocks OS Directory Browsing 
#
# Author: Armand Kruger
#
 
[Definition]
 
failregex = ^<HOST>.*GET.*(?i)ls.*
            ^<HOST>.*GET.*(?i)cd.*
            ^<HOST>.*GET.*(?!)var.*
            ^<HOST>.*GET.*(?!)www.*
            ^<HOST>.*GET.*(?!)idfile.*
            ^<HOST>.*GET.*(?i)mv.*
            ^<HOST>.*GET.*(?!)echo.*
            ^<HOST>.*GET.*(?!)log.*
            ^<HOST>.*GET.*(?!)tmp.*
            ^<HOST>.*GET.*(?!)wget.*
            ^<HOST>.*GET.*(?!)nc.*
            ^<HOST>.*GET.*(?!)id.*
            ^<HOST>.*GET.*(?i)adduser.*
            ^<HOST>.*GET.*(?i)mkdir.*
            ^<HOST>.*GET.*(?i)sudo.*
            ^<HOST>.*GET.*(?i)passwd.*
            ^<HOST>.*GET.*(?!)etc.*
            ^<HOST>.*GET.*(?!)bin.*
            ^<HOST>.*GET.*(?!)cat.*
            ^<HOST>.*GET.*(?!)cmd.*
            ^<HOST>.*GET.*(?!)uname.*
            ^<HOST>.*GET.*(?!)bash.*
            ^<HOST>.*GET.*(?!)ps.*
            ^<HOST>.*GET.*(?!)sh.*

            
            
ignoreregex =
```

### Restart, check & debug

- Restart and check the daemon 
```BASH
sudo systemctl restart fail2ban && \
sudo systemctl status fail2ban
```

- Check the number of active jails
```BASH
sudo fail2ban-client status
```

- Unban an IP
```BASH
fail2ban-client set sshd unbanip 
```
