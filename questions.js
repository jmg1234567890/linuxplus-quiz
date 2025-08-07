const allQuestions = [
  {
    "question": "An administrator accidentally deleted the /boot/vmlinuz file and must resolve the issue before the server is rebooted. Which of the following commands should the administrator use to identify the correct version of this file?",
    "choices": [
      "rpm -qa | grep kernel; uname -a",
      "yum -y update; shutdown -r now",
      "cat /etc/centos-release; rpm -Uvh --nodeps",
      "telinit 1; restorecon -Rv /boot"
    ],
    "answer": "A"
  },
  {
    "question": "A cloud engineer needs to change the secure remote login port from 22 to 49000. Which of the following files should the engineer modify to change the port number to the desired value?",
    "choices": [
      "/etc/host.conf",
      "/etc/hostname",
      "/etc/services",
      "/etc/ssh/sshd_config"
    ],
    "answer": "D"
  },
  {
    "question": "A new file was added to a main Git repository. An administrator wants to synchronize a local copy with the contents of the main repository. Which of the following commands should the administrator use for this task?",
    "choices": [
      "git reflog",
      "git pull",
      "git status",
      "git push"
    ],
    "answer": "B"
  },
  {
    "question": "A Linux administrator needs to redirect all HTTP traffic temporarily to the new proxy server 192.0.2.25 on port 3128. Which of the following commands will accomplish this task?",
    "choices": [
      "iptables -t nat -D PREROUTING -p tcp --sport 80 -j DNAT - -to-destination 192.0.2.25:3128",
      "iptables -t nat -A PREROUTING -p top --dport 81 -j DNAT \u201c-to-destination 192.0.2.25:3129",
      "iptables -t nat -I PREROUTING -p top --sport 80 -j DNAT \u201c-to-destination 192.0.2.25:3129",
      "iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT \u201c-to-destination 192.0.2.25:3128"
    ],
    "answer": "D"
  },
  {
    "question": "Developers have requested implementation of a persistent, static route on the application server. Packets sent over the interface eth0 to 10.0.213.5 should be routed via 10.0.5.1. Which of the following commands should the administrator run to achieve this goal?",
    "choices": [
      "route -i etho -p add 10.0.213.5 10.0.5.1",
      "route modify eth0 +ipv4.routes '10.0.213.5 10.0.5.1'",
      "echo '10.0.213.5 10.0.5.1 eth0' > /proc/net/route",
      "ip route add 10.0.213.5 via 10.0.5.1 dev eth0"
    ],
    "answer": "D"
  },
  {
    "question": "A user is asking the systems administrator for assistance with writing a script to verify whether a file exists. Given the following:  Which of the following commands should replace the <CONDITIONAL> string?",
    "choices": [
      "if [ -f '$filename' ]; then",
      "if [ -d '$filename' ]; then",
      "if [ -f '$filename' ] then",
      "if [ -f '$filename' ]; while"
    ],
    "answer": "A"
  },
  {
    "question": "**INSTRUCTIONS:** Fill in the shell script below.\n\nDRAG DROP As a Systems Administrator, to reduce disk space, you were tasked to create a shell script that does the following: Add relevant content to /tmp/script.sh, so that it finds and compresses rotated files in /var/log  without recursion. **INSTRUCTIONS:** Fill in the missing code below to complete the log rotation script. Answer:  Explanation: QUESTION 8 A systems administrator is deploying three identical, cloud-based servers. The administrator is using the following code to complete the task:  Which of the following technologies is the administrator using?\n\n<pre># /tmp/script.sh\nfind /var/log -maxdepth 1 -name '*.gz' -exec gzip {} \\;</pre>",
    "choices": [
      "Ansible",
      "Puppet",
      "Chef",
      "Terraform"
    ],
    "answer": "D"
  },
  {
    "question": "Which of the following technologies can be used as a central repository of Linux users and groups?",
    "choices": [
      "LDAP",
      "MFA",
      "SSO",
      "PAM"
    ],
    "answer": "A"
  },
  {
    "question": "A systems administrator is troubleshooting connectivity issues and trying to find out why a Linux server is not able to reach other servers on the same subnet it is connected to. When listing link parameters, the following is presented: Based on the output above, which of following is the MOST probable cause of the issue?",
    "choices": [
      "The address ac:00:11:22:33:cd is not a valid Ethernet address.",
      "The Ethernet broadcast address should be ac:00:11:22:33:ff instead.",
      "The network interface eth0 is using an old kernel module. tribalsent@yahoo.com 04 Jul 2025",
      "The network interface cable is not connected to a switch."
    ],
    "answer": "D"
  },
  {
    "question": "A Linux administrator was asked to run a container with the httpd server inside. This container should be exposed at port 443 of a Linux host machine while it internally listens on port 8443. Which of the following commands will accomplish this task?",
    "choices": [
      "podman run -d -p 443:8443 httpd",
      "podman run -d -p 8443:443 httpd",
      "podman run \u201cd -e 443:8443 httpd",
      "podman exec -p 8443:443 httpd"
    ],
    "answer": "A"
  },
  {
    "question": "A Linux administrator needs to analyze a failing application that is running inside a container. Which of the following commands allows the Linux administrator to enter the running container and analyze the logs that are stored inside?",
    "choices": [
      "docker run -ti app /bin/sh",
      "podman exec -ti app /bin/sh",
      "podman run -d app /bin/bash",
      "docker exec -d app /bin/bash"
    ],
    "answer": "B"
  },
  {
    "question": "A systems administrator needs to clone the partition /dev/sdc1 to /dev/sdd1. Which of the following commands will accomplish this task?",
    "choices": [
      "tar -cvzf /dev/sdd1 /dev/sdc1",
      "rsync /dev/sdc1 /dev/sdd1",
      "dd if=/dev/sdc1 of=/dev/sdd1",
      "scp /dev/sdc1 /dev/sdd1"
    ],
    "answer": "C"
  },
  {
    "question": "When trying to log in remotely to a server, a user receives the following message: The server administrator is investigating the issue on the server and receives the following outputs:  Which of the following is causing the issue?",
    "choices": [
      "The wrong permissions are on the users home directory.",
      "The account was locked out due to three failed logins.",
      "The user entered the wrong password.",
      "The user has the wrong shell assigned to the account."
    ],
    "answer": "D"
  },
  {
    "question": "A new Linux systems administrator just generated a pair of SSH keys that should allow connection to the servers. Which of the following commands can be used to copy a key file to remote servers?  (Choose two.)\n<pre>\nOutput 1:\nShell: /bin/false\n\nOutput 2:\ndrwxr-xr-x  jsmith  jsmith  /home/jsmith\n\nOutput 3:\nAccepted password for jsmith from 10.0.0.1 port 22 ssh2\nConnection closed.\n</pre>",
    "choices": [
      "wget",
      "ssh-keygen",
      "ssh-keyscan",
      "ssh-copy-id E. ftpd F. scp"
    ],
    "answer": "D"
  },
  {
    "question": "A systems administrator needs to reconfigure a Linux server to allow persistent IPv4 packet forwarding. Which of the following commands is the correct way to accomplish this task?",
    "choices": [
      "echo 1 > /proc/sys/net/ipv4/ipv_forward",
      "sysctl -w net.ipv4.ip_forward=1",
      "firewall-cmd --enable ipv4_forwarding",
      "systemct1 start ipv4_forwarding"
    ],
    "answer": "B"
  },
  {
    "question": "A Linux administrator would like to use systemd to schedule a job to run every two hours. The administrator creates timer and service definitions and restarts the server to load these new configurations. After the restart, the administrator checks the log file and notices that the job is only running daily. Which of the following is MOST likely causing the issue?",
    "choices": [
      "The checkdiskspace.service is not running.",
      "The checkdiskspace.service needs to be enabled.",
      "The OnCalendar schedule is incorrect in the timer definition.",
      "The system-daemon services need to be reloaded."
    ],
    "answer": "C"
  },
  {
    "question": "An administrator deployed a Linux server that is running a web application on port 6379/tcp. SELinux is in enforcing mode based on organization policies. The port is open on the firewall. Users who are trying to connect to a local instance of the web application receive Error 13, Permission denied. The administrator ran some commands that resulted in the following output:  Which of the following commands should be used to resolve the issue?",
    "choices": [
      "semanage port -d -t http_port_t -p tcp 6379",
      "semanage port -a -t http_port_t -p tcp 6379",
      "semanage port -a http_port_t -p top 6379",
      "semanage port -l -t http_port_tcp 6379"
    ],
    "answer": "B"
  },
  {
    "question": "A systems administrator created a web server for the company and is required to add a tag for the API so end users can connect. Which of the following would the administrator do to complete this requirement?",
    "choices": [
      "hostnamectl status --no-ask-password",
      "hostnamectl set-hostname '$(perl -le 'print' 'A' x 86)'",
      "hostnamectl set-hostname Comptia-WebNode -H root@192.168.2.14  tribalsent@yahoo.com 04 Jul 2025",
      "hostnamectl set-hostname Comptia-WebNode --transient"
    ],
    "answer": "C"
  },
  {
    "question": "A systems administrator wants to back up the directory /data and all its contents to /backup/data on a remote server named remote. Which of the following commands will achieve the desired effect?",
    "choices": [
      "scp -p /data remote:/backup/data",
      "ssh -i /remote:/backup/ /data",
      "rsync -a /data remote:/backup/",
      "cp -r /data /remote/backup/"
    ],
    "answer": "C"
  },
  {
    "question": "An administrator needs to make some changes in the IaC declaration templates. Which of the following commands would maintain version control?",
    "choices": [
      "git clone https://github.com/comptia/linux+-.git git push origin",
      "git clone https://qithub.com/comptia/linux+-.git git fetch New-Branch",
      "git clone https://github.com/comptia/linux+-.git git status",
      "git clone https://github.com/comptia/linuxt+-.git git checkout -b <new-branch>"
    ],
    "answer": "D"
  },
  {
    "question": "An administrator attempts to rename a file on a server but receives the following error. The administrator then runs a few commands and obtains the following output: Which of the following commands should the administrator run NEXT to allow the file to be renamed by any user?",
    "choices": [
      "chgrp reet files",
      "chacl -R 644 files",
      "chown users files",
      "chmod -t files"
    ],
    "answer": "D"
  },
  {
    "question": "Which of the following commands will display the operating system?",
    "choices": [
      "uname -n",
      "uname -s",
      "uname -o",
      "uname -m"
    ],
    "answer": "C"
  },
  {
    "question": "A systems engineer is adding a new 1GB XFS filesystem that should be temporarily mounted under /ops/app. Which of the following is the correct list of commands to achieve this goal?",
    "choices": [
      "B.    C.    D.  tribalsent@yahoo.com 04 Jul 2025   Answer: D    Explanation:   The list of commands in option D is the correct way to achieve the goal. The commands are as  follows:  fallocate -l 1G /ops/app.img creates a 1GB file named app.img under the /ops directory.  mkfs.xfs /ops/app.img formats the file as an XFS filesystem.  mount -o loop /ops/app.img /ops/app mounts the file as a loop device under the /ops/app directory.  The other options are incorrect because they either use the wrong commands  (dd or truncate instead of fallocate), the wrong options (-t or -f instead of -o), or the wrong order of  arguments (/ops/app.img /ops/app instead of /ops/app /ops/app.img). Reference: CompTIA Linux+  (XK0-005) Certification Study Guide, Chapter 10: Managing Storage, pages 323-324.  QUESTION 25  A Linux administrator recently downloaded a software package that is currently in a compressed file.  Which of the following commands will extract the files?    A. unzip -v",
      "bzip2 -z",
      "gzip",
      "funzip"
    ],
    "answer": "C"
  },
  {
    "question": "A Linux administrator is troubleshooting SSH connection issues from one of the workstations. When users attempt to log in from the workstation to a server with the IP address 104.21.75.76, they receive the following message: The administrator reviews the information below:   Which of the following is causing the connectivity issue?",
    "choices": [
      "The workstation has the wrong IP settings.",
      "The sshd service is disabled.",
      "The servers firewall is preventing connections from being made.",
      "The server has an incorrect default gateway configuration."
    ],
    "answer": "C"
  },
  {
    "question": "Which of the following files holds the system configuration for journal when running systemd?",
    "choices": [
      "/etc/systemd/journald.conf",
      "/etc/systemd/systemd-journalctl.conf",
      "/usr/lib/systemd/journalctl.conf",
      "/etc/systemd/systemd-journald.conf"
    ],
    "answer": "A"
  },
  {
    "question": "A Linux administrator is tasked with creating resources using containerization. When deciding how to create this type of deployment, the administrator identifies some key features, including portability, high availability, and scalability in production. Which of the following should the Linux administrator choose for the new design?",
    "choices": [
      "Docker",
      "On-premises systems",
      "Cloud-based systems",
      "Kubernetes"
    ],
    "answer": "D"
  },
  {
    "question": "Which of the following tools is commonly used for creating CI/CD pipelines?",
    "choices": [
      "Chef",
      "Puppet",
      "Jenkins",
      "Ansible"
    ],
    "answer": "C"
  },
  {
    "question": "A systems administrator requires that all files that are created by the user named web have read-only permissions by the owner. Which of the following commands will satisfy this requirement?",
    "choices": [
      "chown web:web /home/web",
      "chmod -R 400 /home/web",
      "echo 'umask 377' >> /home/web/.bashrc",
      "setfacl read /home/web"
    ],
    "answer": "C"
  },
  {
    "question": "A systems administrator is tasked with preventing logins from accounts other than root, while the file /etc/nologin exists. Which of the following PAM modules will accomplish this task?",
    "choices": [
      "pam_login.so",
      "pam_access.so",
      "pam_logindef.so",
      "pam_nologin.so"
    ],
    "answer": "D"
  },
  {
    "question": "A systems administrator has been tasked with disabling the nginx service from the environment to prevent it from being automatically and manually started. Which of the following commands will accomplish this task?",
    "choices": [
      "systemct1 cancel nginx",
      "systemct1 disable nginx",
      "systemct1 mask nginx",
      "systemct1 stop nginx"
    ],
    "answer": "C"
  },
  {
    "question": "A Linux administrator is troubleshooting an issue in which an application service failed to start on a Linux server. The administrator runs a few commands and gets the following outputs: Based on the above outputs, which of the following is the MOST likely action the administrator should take to resolve this issue?",
    "choices": [
      "Enable the logsearch.service and restart the service.",
      "Increase the TimeoutStartUSec configuration for the logsearch.sevice.",
      "Update the OnCalendar configuration to schedule the start of the logsearch.service.",
      "Update the KillSignal configuration for the logsearch.service to use TERM."
    ],
    "answer": "B"
  },
  {
    "question": "A Linux administrator has installed a web server, a database server, and a web application on a server. The web application should be active in order to render the web pages. After the administrator restarts the server, the website displays the following message in the browser: Error establishing a database connection. The Linux administrator reviews the following relevant output from the systemd init files: The administrator needs to ensure that the database is available before the web application is started. Which of the following should the administrator add to the HTTP server .service file to accomplish this task?",
    "choices": [
      "TRIGGERS=mariadb.service",
      "ONFAILURE=mariadb.service",
      "WANTEDBY=mariadb.service",
      "REQUIRES=mariadb.service"
    ],
    "answer": "D"
  },
  {
    "question": "Several users reported that they were unable to write data to the /oracle1 directory. The following output has been provided: Which of the following commands should the administrator use to diagnose the issue?",
    "choices": [
      "df -i /oracle1",
      "fdisk -1 /dev/sdb1",
      "lsblk /dev/sdb1",
      "du -sh /oracle1"
    ],
    "answer": "A"
  },
  {
    "question": "After installing some RPM packages, a systems administrator discovers the last package that was installed was not needed. Which of the following commands can be used to remove the package?",
    "choices": [
      "dnf remove packagename",
      "apt-get remove packagename",
      "rpm -i packagename",
      "apt remove packagename"
    ],
    "answer": "A"
  },
  {
    "question": "A systems administrator is checking the system logs. The administrator wants to look at the last 20 lines of a log. Which of the following will execute the command?",
    "choices": [
      "tail -v 20",
      "tail -n 20",
      "tail -c 20",
      "tail -l 20"
    ],
    "answer": "B"
  },
  {
    "question": "An administrator is trying to diagnose a performance issue and is reviewing the following output: System Properties: CPU: 4 vCPU Memory: 40GB Disk maximum IOPS: 690 Disk maximum throughput: 44Mbps | 44000Kbps Based on the above output, which of the following BEST describes the root cause?",
    "choices": [
      "The system has reached its maximum IOPS, causing the system to be slow.",
      "The system has reached its maximum permitted throughput, therefore iowait is increasing.",
      "The system is mostly idle, therefore the iowait is high.",
      "The system has a partitioned disk, which causes the IOPS to be doubled.  tribalsent@yahoo.com 04 Jul 2025"
    ],
    "answer": "B"
  },
  {
    "question": "A systems administrator wants to test the route between IP address 10.0.2.15 and IP address 192.168.1.40. Which of the following commands will accomplish this task?",
    "choices": [
      "route -e get to 192.168.1.40 from 10.0.2.15",
      "ip route get 192.163.1.40 from 10.0.2.15",
      "ip route 192.169.1.40 to 10.0.2.15",
      "route -n 192.168.1.40 from 10.0.2.15"
    ],
    "answer": "B"
  },
  {
    "question": "A Linux administrator was tasked with deleting all files and directories with names that are contained in the sobelete.txt file. Which of the following commands will accomplish this task?",
    "choices": [
      "xargs -f cat toDelete.txt -rm",
      "rm -d -r -f toDelete.txt",
      "cat toDelete.txt | rm -frd",
      "cat toDelete.txt | xargs rm -rf"
    ],
    "answer": "D"
  },
  {
    "question": "A Linux administrator is troubleshooting the root cause of a high CPU load and average.  Which of the following commands will permanently resolve the issue?",
    "choices": [
      "renice -n -20 6295",
      "pstree -p 6295",
      "iostat -cy 1 5",
      "kill -9 6295"
    ],
    "answer": "D"
  },
  {
    "question": "A Linux administrator wants to set the SUID of a file named dev_team.text with 744 access rights. Which of the following commands will achieve this goal?",
    "choices": [
      "chmod 4744 dev_team.txt",
      "chmod 744 --setuid dev_team.txt",
      "chmod -c 744 dev_team.txt",
      "chmod -v 4744 --suid dev_team.txt"
    ],
    "answer": "A"
  },
  {
    "question": "A developer has been unable to remove a particular data folder that a team no longer uses. The developer escalated the issue to the systems administrator. The following output was received:  Which of the following commands can be used to resolve this issue?",
    "choices": [
      "chgrp -R 755 data/",
      "chmod -R 777 data/",
      "chattr -R -i data/",
      "chown -R data/"
    ],
    "answer": "C"
  },
  {
    "question": "A Linux administrator needs to ensure that Java 7 and Java 8 are both locally available for developers to use when deploying containers. Currently only Java 8 is available. Which of the following commands should the administrator run to ensure both versions are available?",
    "choices": [
      "docker image load java:7",
      "docker image pull java:7",
      "docker image import java:7",
      "docker image build java:7"
    ],
    "answer": "B"
  },
  {
    "question": "A cloud engineer is installing packages during VM provisioning. Which of the following should the engineer use to accomplish this task?",
    "choices": [
      "Cloud-init",
      "Bash",
      "Docker",
      "Sidecar"
    ],
    "answer": "A"
  },
  {
    "question": "A systems administrator is tasked with creating a cloud-based server with a public IP address.  Which of the following technologies did the systems administrator use to complete this task?",
    "choices": [
      "Puppet",
      "Git",
      "Ansible",
      "Terraform"
    ],
    "answer": "D"
  },
  {
    "question": "A Linux systems administrator is setting up a new web server and getting 404 - NOT FOUND errors while trying to access the web server pages from the browser. While working on the diagnosis of this issue, the Linux systems administrator executes the following commands: Which of the following commands will BEST resolve this issue?",
    "choices": [
      "sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config",
      "restorecon -R -v /var/www/html",
      "setenforce 0",
      "setsebool -P httpd_can_network_connect_db on"
    ],
    "answer": "B"
  },
  {
    "question": "To harden one of the servers, an administrator needs to remove the possibility of remote administrative login via the SSH service. Which of the following should the administrator do?",
    "choices": [
      "Add the line DenyUsers root to the /etc/hosts.deny file.",
      "Set PermitRootLogin to no in the /etc/ssh/sshd_config file.",
      "Add the line account required pam_nologin. so to the /etc/pam.d/sshd file.",
      "Set PubKeyAuthentication to no in the /etc/ssh/ssh_config file."
    ],
    "answer": "B"
  },
  {
    "question": "Which of the following is a function of a bootloader?",
    "choices": [
      "It initializes all the devices that are required to load the OS.",
      "It mounts the root filesystem that is required to load the OS.",
      "It helps to load the different kernels to initiate the OS startup process.",
      "It triggers the start of all the system services."
    ],
    "answer": "C"
  },
  {
    "question": "A systems administrator configured firewall rules using firewalld. However, after the system is rebooted, the firewall rules are not present: The systems administrator makes additional checks: Which of the following is the reason the firewall rules are not active?",
    "choices": [
      "iptables is conflicting with firewalld. tribalsent@yahoo.com 04 Jul 2025",
      "The wrong system target is activated.",
      "FIREWALL_ARGS has no value assigned.",
      "The firewalld service is not enabled."
    ],
    "answer": "D"
  },
  {
    "question": "A newly created container has been unable to start properly, and a Linux administrator is analyzing the cause of the failure. Which of the following will allow the administrator to determine the FIRST command that is executed inside the container right after it starts?",
    "choices": [
      "docker export <container_id>",
      "docker info <container_id>",
      "docker start <container_id>",
      "docker inspect <container_id>"
    ],
    "answer": "D"
  },
  {
    "question": "A Linux administrator is scheduling a system job that runs a script to check available disk space every hour. The Linux administrator does not want users to be able to start the job. Given the following:  The Linux administrator attempts to start the timer service but receives the following error message: Which of the following is MOST likely the reason the timer will not start?",
    "choices": [
      "The checkdiskspace.timer unit should be enabled via systemct1.",
      "The timers.target should be reloaded to get the new configuration.",
      "The checkdiskspace.timer should be configured to allow manual starts.",
      "The checkdiskspace.timer should be started using the sudo command."
    ],
    "answer": "C"
  },
  {
    "question": "A Linux administrator wants to find out whether files from the wget package have been altered since they were installed. Which of the following commands will provide the correct information?",
    "choices": [
      "rpm -i wget",
      "rpm -qf wget",
      "rpm -F wget",
      "rpm -V wget"
    ],
    "answer": "D"
  },
  {
    "question": "A Linux engineer set up two local DNS servers (10.10.10.10 and 10.10.10.20) and was testing email connectivity to the local mail server using the mail command on a local machine when the following error appeared: The local machine DNS settings are: Which of the following commands could the engineer use to query the DNS server to get mail server information?",
    "choices": [
      "dig @example.com 10.10.10.20 a",
      "dig @10.10.10.20 example.com mx",
      "dig @example.com 10.10.10.20 ptr",
      "dig @10.10.10.20 example.com ns"
    ],
    "answer": "B"
  },
  {
    "question": "A Linux engineer has been notified about the possible deletion of logs from the file /opt/app/logs. The engineer needs to ensure the log file can only be written into without removing previous entries. Which of the following commands would be BEST to use to accomplish this task?",
    "choices": [
      "chattr +a /opt/app/logs",
      "chattr +d /opt/app/logs",
      "chattr +i /opt/app/logs",
      "chattr +c /opt/app/logs"
    ],
    "answer": "A"
  },
  {
    "question": "A systems administrator needs to check if the service systemd-resolved.service is running without any errors. Which of the following commands will show this information?",
    "choices": [
      "systemct1 status systemd-resolved.service",
      "systemct1 enable systemd-resolved.service",
      "systemct1 mask systemd-resolved.service",
      "systemct1 show systemd-resolved.service"
    ],
    "answer": "A"
  },
  {
    "question": "Junior system administrator had trouble installing and running an Apache web server on a Linux server. You have been tasked with installing the Apache web server on the Linux server and resolving the issue that prevented the junior administrator from running Apache. INSTRUCTIONS Install Apache and start the service. Verify that the Apache service is running with the defaults. Typing \u0153help in the terminal will show a list of relevant event commands. If at any time you would like to bring back the initial state of the simulation, please click the Reset All button.  Answer: See the explanation below. Explanation: yum install httpd systemct1 --now enable httpd systemct1 status httpd netstat -tunlp | grep 80 pkill <processname> systemct1 restart httpd systemct1 status httpd QUESTION 58 A Linux administrator needs to remove software from the server. Which of the following RPM options should be used?",
    "choices": [
      "rpm -s",
      "r\u00d1\u20acm -d",
      "rpm -q",
      "rpm -e"
    ],
    "answer": "D"
  },
  {
    "question": "A Linux system fails to start and delivers the following error message: Which of the following commands can be used to address this issue?",
    "choices": [
      "fsck.ext4 /dev/sda1",
      "partprobe /dev/sda1",
      "fdisk /dev/sda1",
      "mkfs.ext4 /dev/sda1"
    ],
    "answer": "A"
  },
  {
    "question": "Based on an organizations new cybersecurity policies, an administrator has been instructed to ensure that, by default, all new users and groups that are created fall within the specified values below. To which of the following configuration files will the required changes need to be made?",
    "choices": [
      "/etc/login.defs",
      "/etc/security/limits.conf",
      "/etc/default/useradd",
      "/etc/profile"
    ],
    "answer": "A"
  },
  {
    "question": "A Linux administrator is trying to remove the ACL from the file /home/user/dat a. txt but receives the following error message: Given the following analysis:  Which of the following is causing the error message?",
    "choices": [
      "The administrator is not using a highly privileged account.",
      "The filesystem is mounted with the wrong options.",
      "SELinux file context is denying the ACL changes.",
      "File attributes are preventing file modification."
    ],
    "answer": "D"
  },
  {
    "question": "A Linux administrator needs to create a new cloud.cpio archive containing all the files from the current directory. Which of the following commands can help to accomplish this task?",
    "choices": [
      "ls | cpio -iv > cloud.epio",
      "ls | cpio -iv < cloud.epio",
      "ls | cpio -ov > cloud.cpio",
      "ls cpio -ov < cloud.cpio"
    ],
    "answer": "C"
  },
  {
    "question": "A systems administrator made some changes in the ~/.bashrc file and added an alias command. When the administrator tried to use the alias command, it did not work. Which of the following should be executed FIRST?",
    "choices": [
      "source ~/.bashrc",
      "read ~/.bashrc  tribalsent@yahoo.com 04 Jul 2025",
      "touch ~/.bashrc",
      "echo ~/.bashrc"
    ],
    "answer": "A"
  },
  {
    "question": "A junior systems administrator has just generated public and private authentication keys for passwordless login. Which of the following files will be moved to the remote servers?",
    "choices": [
      "id_dsa.pem",
      "id_rsa",
      "id_ecdsa",
      "id_rsa.pub"
    ],
    "answer": "D"
  },
  {
    "question": "A Linux administrator cloned an existing Linux server and built a new server from that clone. The administrator encountered the following error after booting the cloned server: The administrator performed the commands listed below to further troubleshoot and mount the missing filesystem: Which of the following should administrator use to resolve the device mismatch issue and mount the disk?",
    "choices": [
      "mount disk by device-id",
      "fsck -A",
      "mount disk by-label",
      "mount disk by-blkid"
    ],
    "answer": "A"
  },
  {
    "question": "A systems administrator installed a new software program on a Linux server. When the systems administrator tries to run the program, the following message appears on the screen. Which of the following commands will allow the systems administrator to check whether the system supports virtualization?",
    "choices": [
      "dmidecode -s system-version",
      "lscpu",
      "sysctl -a",
      "cat /sys/device/system/cpu/possible"
    ],
    "answer": "B"
  },
  {
    "question": "A Linux administrator created the directory /project/access2all. By creating this directory, the administrator is trying to avoid the deletion or modification of files from non-owners. Which of the following will accomplish this goal?",
    "choices": [
      "chmod +t /project/access2all",
      "chmod +rws /project/access2all",
      "chmod 2770 /project/access2all",
      "chmod ugo+rwx /project/access2all"
    ],
    "answer": "A"
  },
  {
    "question": "A Linux systems administrator needs to persistently enable IPv4 forwarding in one of the Linux systems. Which of the following commands can be used together to accomplish this task? (Choose two.)",
    "choices": [
      "sysctl net.ipv4.ip_forward",
      "sysctl -w net.ipv4.ip_forward=1",
      "echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf",
      "echo 1 > /proc/sys/net/ipv4/ip_forward  E. sysctl \u201cp  F. echo 'net.ipv6.conf.all.forwarding=l' >> /etc/sysctl.conf"
    ],
    "answer": "B"
  },
  {
    "question": "Due to low disk space, a Linux administrator finding and removing all log files that were modified more than 180 days ago. Which of the following commands will accomplish this task?",
    "choices": [
      "find /var/log -type d -mtime +180 -print -exec rm {} \\\\;",
      "find /var/log -type f -modified +180 -rm",
      "find /var/log -type f -mtime +180 -exec rm {} \\\\",
      "find /var/log -type c -atime +180 \u201cremove"
    ],
    "answer": "C"
  },
  {
    "question": "A junior administrator is setting up a new Linux server that is intended to be used as a router at a remote site. Which of the following parameters will accomplish this goal?",
    "choices": [
      "B.  tribalsent@yahoo.com 04 Jul 2025   C.    D.    Answer: C    Explanation:   The parameter net.ipv4.ip_forward=1 will accomplish the goal of setting up a new Linux server as a  router. This parameter enables the IP forwarding feature, which allows the server to forward packets  between different network interfaces. This is necessary for a router to route traffic between different  networks. The parameter can be set in the /etc/sysctl.conf file or by using the sysctl command. This is  the correct parameter to use to accomplish the goal. The other options are incorrect because they  either do not exist (net.ipv4.ip_forwarding or net.ipv4.ip_route) or do not enable IP forwarding  (net.ipv4.ip_forward=0). Reference: CompTIA Linux+ (XK0-005) Certification Study Guide, Chapter  12: Managing Network Connections, page 382.  QUESTION 71  Some servers in an organization have been compromised. Users are unable to access to the  organizations web page and other services. While reviewing the system log, a systems administrator  notices messages from the kernel regarding firewall rules:  tribalsent@yahoo.com 04 Jul 2025   Which of the following commands will remediate and help resolve the issue?  A.",
      "C.  tribalsent@yahoo.com 04 Jul 2025   D.    Answer: A    Explanation:   The command iptables -F will remediate and help resolve the issue. The issue is caused by the  firewall rules that block the access to the organizations web page and other services. The output  of dmesg | grep firewall shows that the kernel has dropped packets from the source IP address  192.168.1.100 to the destination port 80, which is the default port for HTTP. The command iptables -  F will flush all the firewall rules and allow the traffic to pass through. This command will resolve the  issue and restore the access to the web page and other services. The other options are incorrect  because they either do not affect the firewall rules (ip route flush or ip addr flush) or do not exist  (iptables -R). Reference: CompTIA Linux+ (XK0-005) Certification Study Guide, Chapter 18: Securing  Linux Systems, page 543.  QUESTION 72  A junior administrator is trying to set up a passwordless SSH connection to one of the servers. The  administrator follows the instructions and puts the key in the authorized_key file at the server, but  the administrator is still asked to provide a password during the connection.  Given the following output:  tribalsent@yahoo.com 04 Jul 2025   Which of the following commands would resolve the issue and allow an SSH connection to be  established without a password?    A. restorecon -rv .ssh/authorized_key  B. mv .ssh/authorized_key .ssh/authorized_keys",
      "systemct1 restart sshd.service",
      "chmod 600 mv .ssh/authorized_key"
    ],
    "answer": "B"
  },
  {
    "question": "A Linux administrator needs to resolve a service that has failed to start. The administrator runs the following command: The following output is returned  Which of the following is MOST likely the issue?",
    "choices": [
      "The service does not have permissions to read write the startupfile.",
      "The service startupfile size cannot be 81k.",
      "The service startupfile cannot be owned by root.",
      "The service startupfile should not be owned by the root group."
    ],
    "answer": "A"
  },
  {
    "question": "A Linux engineer is setting the sticky bit on a directory called devops with 755 file permission. Which of the following commands will accomplish this task?",
    "choices": [
      "chown -s 755 devops",
      "chown 1755 devops",
      "chmod -s 755 devops",
      "chmod 1755 devops"
    ],
    "answer": "D"
  },
  {
    "question": "A Linux administrator booted up the server and was presented with a non-GUI terminal. The administrator ran the command systemct1 isolate graphical.target and rebooted the system by running systemct1 reboot, which fixed the issue. However, the next day the administrator was presented again with a non-GUI terminal. Which of the following is the issue?",
    "choices": [
      "The administrator did not reboot the server properly.",
      "The administrator did not set the default target to basic.target.",
      "The administrator did not set the default target to graphical.target.",
      "The administrator did not shut down the server properly."
    ],
    "answer": "C"
  },
  {
    "question": "Users report that connections to a MariaDB service are being closed unexpectedly. A systems administrator troubleshoots the issue and finds the following message in /var/log/messages: Which of the following is causing the connection issue?",
    "choices": [
      "The process mysqld is using too many semaphores.",
      "The server is running out of file descriptors.",
      "Something is starving the server resources.",
      "The amount of RAM allocated to the server is too high."
    ],
    "answer": "B"
  },
  {
    "question": "A developer is trying to install an application remotely that requires a graphical interface for installation. The developer requested assistance to set up the necessary environment variables along with X11 forwarding in SSH. Which of the following environment variables must be set in remote shell in order to launch the graphical interface?",
    "choices": [
      "$RHOST",
      "SETENV",
      "$SHELL",
      "$DISPLAY"
    ],
    "answer": "D"
  },
  {
    "question": "A systems administrator is implementing a new service task with systems at startup and needs to execute a script entitled test.sh with the following content:  The administrator tries to run the script after making it executable with chmod +x; however, the script will not run. Which of the following should the administrator do to address this issue? (Choose two.)",
    "choices": [
      "Add #!/bin/bash to the bottom of the script.",
      "Create a unit file for the new service in /etc/systemd/system/ with the name helpme.service in the  location.",
      "Add #!//bin/bash to the top of the script.",
      "Restart the computer to enable the new service.  E. Create a unit file for the new service in /etc/init.d with the name helpme.service in the location.  F. Shut down the computer to enable the new service."
    ],
    "answer": "B"
  },
  {
    "question": "A Linux administrator needs to correct the permissions of a log file on the server. Which of the following commands should be used to set filename.log permissions to -rwxr\u201dr--. ?",
    "choices": [
      "chmod 755 filename.log",
      "chmod 640 filename.log",
      "chmod 740 filename.log",
      "chmod 744 filename.log"
    ],
    "answer": "A"
  },
  {
    "question": "After listing the properties of a system account, a systems administrator wants to remove the expiration date of a user account. Which of the following commands will accomplish this task?",
    "choices": [
      "chgrp system accountname",
      "passwd \u201cs accountname  tribalsent@yahoo.com 04 Jul 2025",
      "chmod -G system account name",
      "chage -E -1 accountname"
    ],
    "answer": "D"
  },
  {
    "question": "A systems administrator wants to be sure the sudo rules just added to /etc/sudoers are valid. Which of the following commands can be used for this task?",
    "choices": [
      "visudo -c",
      "test -f /etc/sudoers",
      "sudo vi check",
      "cat /etc/sudoers | tee test"
    ],
    "answer": "A"
  },
  {
    "question": "A user generated a pair of private-public keys on a workstation. Which of the following commands will allow the user to upload the public key to a remote server and enable passwordless login?",
    "choices": [
      "scp ~/.ssh/id_rsa user@server:~/",
      "rsync ~ /.ssh/ user@server:~/",
      "ssh-add user server",
      "ssh-copy-id user@server"
    ],
    "answer": "D"
  },
  {
    "question": "A Linux administrator created a new file system. Which of the following files must be updated to ensure the filesystem mounts at boot time?",
    "choices": [
      "/etc/sysctl",
      "/etc/filesystems",
      "/etc/fstab",
      "/etc/nfsmount.conf"
    ],
    "answer": "C"
  },
  {
    "question": "A Linux administrator is troubleshooting a memory-related issue. Based on the output of the commands: Which of the following commands would address the issue?",
    "choices": [
      "top -p 8321",
      "kill -9 8321",
      "renice -10 8321",
      "free 8321"
    ],
    "answer": "B"
  },
  {
    "question": "A systems administrator made some unapproved changes prior to leaving the company. The newly hired administrator has been tasked with revealing the system to a compliant state. Which of the following commands will list and remove the correspondent packages?",
    "choices": [
      "dnf list and dnf remove last",
      "dnf remove and dnf check",
      "dnf info and dnf upgrade",
      "dnf history and dnf history undo last"
    ],
    "answer": "D"
  },
  {
    "question": "An administrator transferred a key for SSH authentication to a home directory on a remote server. The key file was moved to .ssh/authorized_keys location in order to establish SSH connection without a password. However, the SSH command still asked for the password. Given the following output: Which of the following commands would resolve the issue?",
    "choices": [
      "restorecon .ssh/authorized_keys",
      "ssh_keygen -t rsa -o .ssh/authorized_keys",
      "chown root:root .ssh/authorized_keys",
      "chmod 600 .ssh/authorized_keys"
    ],
    "answer": "D"
  },
  {
    "question": "A cloud engineer needs to remove all dangling images and delete all the images that do not have an associated container. Which of the following commands will help to accomplish this task?",
    "choices": [
      "docker images prune -a",
      "docker push images -a",
      "docker rmi -a images",
      "docker images rmi --all"
    ],
    "answer": "A"
  },
  {
    "question": "A Linux system is failing to boot with the following error:  Which of the following actions will resolve this issue? (Choose two.)",
    "choices": [
      "Execute grub-install --root-directory=/mnt and reboot.",
      "Execute grub-install /dev/sdX and reboot.",
      "Interrupt the boot process in the GRUB menu and add rescue to the kernel line.",
      "Fix the partition modifying /etc/default/grub and reboot.  E. Interrupt the boot process in the GRUB menu and add single to the kernel line.  F. Boot the system on a LiveCD/ISO."
    ],
    "answer": "B"
  },
  {
    "question": "A Linux administrator needs to create an image named sda.img from the sda disk and store it in the  /tmp directory. Which of the following commands should be used to accomplish this task?",
    "choices": [
      "dd of=/dev/sda if=/tmp/sda.img",
      "dd if=/dev/sda of=/tmp/sda.img",
      "dd --if=/dev/sda --of=/tmp/sda.img",
      "dd --of=/dev/sda --if=/tmp/sda.img"
    ],
    "answer": "B"
  },
  {
    "question": "A Linux administrator is creating a primary partition on the replacement hard drive for an application server. Which of the following commands should the administrator issue to verify the device name of this partition?",
    "choices": [
      "sudo fdisk /dev/sda",
      "sudo fdisk -s /dev/sda",
      "sudo fdisk -l",
      "sudo fdisk -h"
    ],
    "answer": "C"
  },
  {
    "question": "A systems administrator is investigating why one of the servers has stopped connecting to the internet. Which of the following is causing the issue?",
    "choices": [
      "The DNS address has been commented out in the configuration file.",
      "The search entry in the /etc/resolv.conf file is incorrect.",
      "Wired connection 1 is offline.",
      "No default route is defined.  tribalsent@yahoo.com 04 Jul 2025"
    ],
    "answer": "D"
  },
  {
    "question": "A systems administrator is tasked with installing GRUB on the legacy MBR of the SATA hard drive. Which of the following commands will help the administrator accomplish this task?",
    "choices": [
      "grub-install /dev/hda",
      "grub-install /dev/sda",
      "grub-install /dev/sr0",
      "grub-install /dev/hd0,0"
    ],
    "answer": "B"
  },
  {
    "question": "A junior Linux administrator is tasked with installing an application. The installation guide states the application should only be installed in a run level 5 environment. Which of the following commands would ensure the server is set to runlevel 5?",
    "choices": [
      "systemct1 isolate multi-user.target",
      "systemct1 isolate graphical.target",
      "systemct1 isolate network.target",
      "systemct1 isolate basic.target"
    ],
    "answer": "B"
  },
  {
    "question": "A Linux administrator is tasked with adding users to the system. However, the administrator wants to ensure the users access will be disabled once the project is over. The expiration date should be 2021- 09-30. Which of the following commands will accomplish this task?",
    "choices": [
      "sudo useradd -e 2021-09-30 Project_user",
      "sudo useradd -c 2021-09-30 Project_user",
      "sudo modinfo -F 2021-09-30 Project_uses",
      "sudo useradd -m -d 2021-09-30 Project_user"
    ],
    "answer": "A"
  },
  {
    "question": "A DevOps engineer needs to download a Git repository from https://git.company.com/admin/project.git. Which of the following commands will achieve this goal?",
    "choices": [
      "git clone https://git.company.com/admin/project.git",
      "git checkout https://git.company.com/admin/project.git",
      "git pull https://git.company.com/admin/project.git",
      "git branch https://git.company.com/admin/project.git"
    ],
    "answer": "A"
  },
  {
    "question": "An administrator installed an application from source into /opt/operations1/ and has received numerous reports that users are not able to access the application without having to use the full path /opt/operations1/bin/*. Which of the following commands should be used to resolve this issue?",
    "choices": [
      "echo 'export PATH=$PATH:/opt/operations1/bin' >> /etc/profile",
      "echo 'export PATH=/opt/operations1/bin' >> /etc/profile",
      "echo 'export PATH=$PATH/opt/operations1/bin' >> /etc/profile",
      "echo 'export $PATH:/opt/operations1/bin' >> /etc/profile"
    ],
    "answer": "A"
  },
  {
    "question": "A Linux system is getting an error indicating the root filesystem is full. Which of the following commands should be used by the systems administrator to resolve this issue? (Choose three.)",
    "choices": [
      "df -h /",
      "fdisk -1 /dev/sdb",
      "growpart /dev/mapper/rootvg-rootlv",
      "pvcreate /dev/sdb  E. lvresize \u201cL +10G -r /dev/mapper/rootvg-rootlv  F. lsblk /dev/sda  G. parted -l /dev/mapper/rootvg-rootlv  H. vgextend /dev/rootvg /dev/sdb"
    ],
    "answer": "A"
  },
  {
    "question": "A cloud engineer is asked to copy the file deployment.yaml from a container to the host where the container is running. Which of the following commands can accomplish this task?",
    "choices": [
      "docker cp container_id/deployment.yaml deployment.yaml",
      "docker cp container_id:/deployment.yaml deployment.yaml",
      "docker cp deployment.yaml local://deployment.yaml",
      "docker cp container_id/deployment.yaml local://deployment.yaml"
    ],
    "answer": "B"
  },
  {
    "question": "A Linux system is failing to start due to issues with several critical system processes. Which of the following options can be used to boot the system into the single user mode? (Choose two.)",
    "choices": [
      "Execute the following command from the GRUB rescue shell: mount -o remount, ro/sysroot.",
      "Interrupt the boot process in the GRUB menu and add systemd.unit=single in the kernel line.",
      "Interrupt the boot process in the GRUB menu and add systemd.unit=rescue.target in the kernel  line.",
      "Interrupt the boot process in the GRUB menu and add single=user in the kernel line.  E. Interrupt the boot process in the GRUB menu and add init=/bin/bash in the kernel line.  F. Interrupt the boot process in the GRUB menu and add systemd.unit=single.target in the kernel  line."
    ],
    "answer": "C"
  },
  {
    "question": "A DevOps engineer needs to allow incoming traffic to ports in the range of 4000 to 5000 on a Linux server. Which of the following commands will enforce this rule?",
    "choices": [
      "iptables -f filter -I INPUT -p tcp --dport 4000:5000 -A ACCEPT",
      "iptables -t filter -A INPUT -p tcp --dport 4000:5000 -j ACCEPT",
      "iptables filter -A INPUT -p tcp --dport 4000:5000 -D ACCEPT",
      "iptables filter -S INPUT -p tcp --dport 4000:5000 -A ACCEPT"
    ],
    "answer": "B"
  },
  {
    "question": "A Linux administrator needs to determine whether a hostname is in the DNS. Which of the following would supply the information that is needed?",
    "choices": [
      "nslookup",
      "rsyn\u00d1",
      "netstat",
      "host"
    ],
    "answer": "A"
  },
  {
    "question": "A server is experiencing intermittent connection issues. Some connections to the Internet work as intended, but some fail as if there is no connectivity. The systems administrator inspects the server configuration:  Which of the following is MOST likely the cause of the issue?",
    "choices": [
      "An internal-only DNS server is configured.",
      "The IP netmask is wrong for ens3.",
      "Two default routes are configured.",
      "The ARP table contains incorrect entries."
    ],
    "answer": "C"
  },
  {
    "question": "A cloud engineer needs to block the IP address 192.168.10.50 from accessing a Linux server. Which of the following commands will achieve this goal?",
    "choices": [
      "iptables -F INPUT -j 192.168.10.50 -m DROP",
      "iptables -A INPUT -s 192.168.10.30 -j DROP",
      "iptables -i INPUT --ipv4 192.168.10.50 -z DROP",
      "iptables -j INPUT 192.168.10.50 -p DROP"
    ],
    "answer": "B"
  },
  {
    "question": "A Linux systems administrator is configuring a new filesystem that needs the capability to be mounted persistently across reboots. Which of the following commands will accomplish this task? (Choose two.)",
    "choices": [
      "df -h /data",
      "mkfs.ext4 /dev/sdc1",
      "fsck /dev/sdc1",
      "fdisk -l /dev/sdc1  E. echo '/data /dev/sdc1 ext4 defaults 0 0' >> /etc/fstab  F. echo '/dev/sdc1 /data ext4 defaults 0 0' >> /etc/fstab"
    ],
    "answer": "B"
  },
  {
    "question": "A Linux administrator is alerted to a storage capacity issue on a server without a specific mount point or directory. Which of the following commands would be MOST helpful for troubleshooting? (Choose two.)",
    "choices": [
      "parted",
      "df",
      "mount",
      "du  E. fdisk  F. dd  G. ls"
    ],
    "answer": "B"
  },
  {
    "question": "A systems administrator pressed Ctrl+Z after starting a program using the command line, and the shell prompt was presented. In order to go back to the program, which of the following commands can the administrator use?",
    "choices": [
      "fg",
      "su",
      "bg",
      "ed"
    ],
    "answer": "A"
  },
  {
    "question": "A systems administrator received a notification that a system is performing slowly. When running the top command, the systems administrator can see the following values: Which of the following commands will the administrator most likely run NEXT?",
    "choices": [
      "vmstat",
      "strace",
      "htop",
      "lsof"
    ],
    "answer": "A"
  },
  {
    "question": "Which of the following technologies provides load balancing, encryption, and observability in containerized environments?",
    "choices": [
      "Virtual private network",
      "Sidecar pod",
      "Overlay network",
      "Service mesh"
    ],
    "answer": "D"
  },
  {
    "question": "A development team asks an engineer to guarantee the persistency of journal log files across system reboots. Which of the following commands would accomplish this task?",
    "choices": [
      "grep -i auto /etc/systemd/journald.conf && systemct1 restart systemd-journald.service",
      "cat /etc/systemd/journald.conf | awk '(print $1,$3)'",
      "sed -i 's/auto/persistent/g' /etc/systemd/journald.conf && sed -i 'persistent/s/\u00cb\u2020#//q'  /etc/systemd/journald.conf",
      "journalctl --list-boots && systemct1 restart systemd-journald.service"
    ],
    "answer": "C"
  },
  {
    "question": "A systems administrator is receiving tickets from users who cannot reach the application app that should be listening on port 9443/tcp on a Linux server. To troubleshoot the issue, the systems administrator runs netstat and receives the following output: Based on the information above, which of the following is causing the issue?",
    "choices": [
      "The IP address 0.0.0.0 is not valid.",
      "The application is listening on the loopback interface.",
      "The application is listening on port 1234.",
      "The application is not running."
    ],
    "answer": "B"
  },
  {
    "question": "A systems administrator is troubleshooting a connectivity issue pertaining to access to a system named db.example.com. The system IP address should be 192.168.20.88. The administrator issues the dig command and receives the following output: The administrator runs grep db.example.com /etc/hosts and receives the following output: Given this scenario, which of the following should the administrator do to address this issue?",
    "choices": [
      "Modify the /etc/hosts file and change the db.example.com entry to 192.168.20.89.",
      "Modify the /etc/network file and change the db.example.com entry to 192.168.20.88.",
      "Modify the /etc/network file and change the db.example.com entry to 192.168.20.89.",
      "Modify the /etc/hosts file and change the db.example.com entry to 192.168.20.88."
    ],
    "answer": "D"
  },
  {
    "question": "Users have been unable to reach www.comptia.org from a Linux server. A systems administrator is troubleshooting the issue and does the following:  Based on the information above, which of the following is causing the issue?",
    "choices": [
      "The name www.comptia.org does not point to a valid IP address.",
      "The server 192.168.168.53 is unreachable.",
      "No default route is set on the server.",
      "The network interface eth0 is disconnected."
    ],
    "answer": "B"
  },
  {
    "question": "A systems technician is working on deploying several microservices to various RPM-based systems, some of which could run up to two hours. Which of the following commands will allow the technician to execute those services and continue deploying other microservices within the same terminal section?",
    "choices": [
      "gedit & disown",
      "kill 9 %1",
      "fg %1",
      "bg %1 job name"
    ],
    "answer": "D"
  },
  {
    "question": "A Linux administrator was notified that a virtual server has an I/O bottleneck. The Linux administrator analyzes the following output: Given there is a single CPU in the sever, which of the following is causing the slowness?",
    "choices": [
      "The system is running out of swap space.  tribalsent@yahoo.com 04 Jul 2025",
      "The CPU is overloaded.",
      "The memory is exhausted.",
      "The processes are paging."
    ],
    "answer": "B"
  },
  {
    "question": "Employees in the finance department are having trouble accessing the file /opt/work/file. All IT employees can read and write the file. Systems administrator reviews the following output: Which of the following commands would permanently fix the access issue while limiting access to IT and finance department employees?",
    "choices": [
      "chattr +i file",
      "chown it:finance file",
      "chmod 666 file",
      "setfacl -m g:finance:rw file"
    ],
    "answer": "D"
  },
  {
    "question": "A Linux engineer needs to create a custom script, cleanup.sh, to run at boot as part of the system services. Which of the following processes would accomplish this task?",
    "choices": [
      "Create a unit file in the /etc/default/ directory.  systemct1 enable cleanup  systemct1 is-enabled cleanup",
      "Create a unit file in the /etc/ske1/ directory.  systemct1 enable cleanup  systemct1 is-enabled cleanup",
      "Create a unit file in the /etc/systemd/system/ directory.  systemct1 enable cleanup  systemct1 is-enabled cleanup",
      "Create a unit file in the /etc/sysctl.d/ directory.  systemct1 enable cleanup  systemct1 is-enabled cleanup    tribalsent@yahoo.com 04 Jul 2025"
    ],
    "answer": "C"
  },
  {
    "question": "A Linux system is failing to boot. The following error is displayed in the serial console: [[1;33mDEPEND[Om] Dependency failed for /data. [[1;33mDEPEND[Om] Dependency failed for Local File Systems ... Welcome to emergency mode! After logging in, type 'journalctl -xb' to viewsystem logs, 'systemct1 reboot' to reboot, 'systemct1 default' to try again to boot into default mode. Give root password for maintenance (or type Control-D to continue} Which of the following files will need to be modified for this server to be able to boot again?",
    "choices": [
      "/etc/mtab",
      "/dev/sda",
      "/etc/fstab",
      "/ete/grub.conf"
    ],
    "answer": "C"
  },
  {
    "question": "A systems administrator frequently connects to a remote host via SSH and a non-standard port. The systems administrator would like to avoid passing the port parameter on the command line every time. Which of the following files can be used to set a different port value for that host?",
    "choices": [
      "/etc/ssh/sshd_config",
      "/etc/ssh/moduli",
      "~/.ssh/config",
      "~/.ssh/authorized_keys"
    ],
    "answer": "C"
  },
  {
    "question": "A Linux administrator modified the SSH configuration file. Which of the following commands should be used to apply the configuration changes?",
    "choices": [
      "systemct1 stop sshd",
      "systemct1 mask sshd",
      "systemct1 reload sshd",
      "systemct1 start sshd"
    ],
    "answer": "C"
  },
  {
    "question": "A cloud engineer needs to check the link status of a network interface named eth1 in a Linux server. Which of the following commands can help to achieve the goal?",
    "choices": [
      "ifconfig hw eth1",
      "netstat -r eth1",
      "ss -ti eth1",
      "ip link show eth1"
    ],
    "answer": "D"
  },
  {
    "question": "A systems administrator is tasked with setting up key-based SSH authentication. In which of the following locations should the administrator place the public keys for the server?",
    "choices": [
      "~/.sshd/authkeys",
      "~/.ssh/keys",
      "~/.ssh/authorized_keys",
      "~/.ssh/keyauth"
    ],
    "answer": "C"
  },
  {
    "question": "A Linux administrator needs to create a new user named user02. However, user02 must be in a different home directory, which is under /comptia/projects. Which of the following commands will accomplish this task?",
    "choices": [
      "useradd -d /comptia/projects user02",
      "useradd -m /comptia/projects user02",
      "useradd -b /comptia/projects user02",
      "useradd -s /comptia/projects user02"
    ],
    "answer": "A"
  },
  {
    "question": "One leg of an LVM-mirrored volume failed due to the underlying physical volume, and a systems administrator is troubleshooting the issue. The following output has been provided: Given this scenario, which of the following should the administrator do to recover this volume?",
    "choices": [
      "Reboot the server. The volume will automatically go back to linear mode.",
      "Replace the failed drive and reconfigure the mirror.",
      "Reboot the server. The volume will revert to stripe mode.",
      "Recreate the logical volume."
    ],
    "answer": "B"
  },
  {
    "question": "A systems administrator created a new Docker image called test. After building the image, the administrator forgot to version the release. Which of the following will allow the administrator to assign the v1 version to the image?",
    "choices": [
      "docker image save test test:v1",
      "docker image build test:vl",
      "docker image tag test test:vl",
      "docker image version test:v1"
    ],
    "answer": "C"
  },
  {
    "question": "A Linux systems administrator receives a notification that one of the servers filesystems is full. Which of the following commands would help the administrator to identify this filesystem?",
    "choices": [
      "lsblk",
      "fdisk",
      "df -h",
      "du -ah"
    ],
    "answer": "C"
  },
  {
    "question": "A systems administrator is notified that the mysqld process stopped unexpectedly. The systems administrator issues the following command: sudo grep \u201ci -r \u02dcout of memory /var/log The output of the command shows the following: kernel: Out of memory: Kill process 9112 (mysqld) score 511 or sacrifice child. Which of the following commands should the systems administrator execute NEXT to troubleshoot this issue? (Select two).",
    "choices": [
      "free -h",
      "nc -v 127.0.0.1 3306",
      "renice -15 $( pidof mysql )",
      "lsblk  E. killall -15  F. vmstat -a 1 4"
    ],
    "answer": "A"
  },
  {
    "question": "Users have reported that the interactive sessions were lost on a Linux server. A Linux administrator verifies the server was switched to rescue.target mode for maintenance. Which of the following commands will restore the server to its usual target?",
    "choices": [
      "telinit 0",
      "systemct1 reboot",
      "systemct1 get-default",
      "systemct1 emergency"
    ],
    "answer": "B"
  },
  {
    "question": "A systems administrator was tasked with assigning the temporary IP address/netmask 192.168.168.1.255.255.255 to the interface eth0 of a Linux server. When adding the address, the following error appears: # ip address add 192.168.168.1 dev eth0 Error: any valid prefix is expected rather than '192.168.168.1'. Based on the command and its output above, which of the following is the cause of the issue?",
    "choices": [
      "The CIDR value should be instead.",
      "There is no route to 192.168.168.1.",
      "The interface eth0 does not exist.",
      "The IP address 192.168.168.1 is already in use."
    ],
    "answer": "A"
  },
  {
    "question": "A Linux user reported the following error after trying to connect to the system remotely: ssh: connect to host 10.0.1.10 port 22: Resource temporarily unavailable The Linux systems administrator executed the following commands in the Linux system while trying to diagnose this issue:  Which of the following commands will resolve this issue?",
    "choices": [
      "firewall-cmd --zone=public --permanent --add-service=22",
      "systemct1 enable firewalld; systemct1 restart firewalld",
      "firewall-cmd --zone=public --permanent --add-service=ssh",
      "firewall-cmd --zone=public --permanent --add-port=22/udp"
    ],
    "answer": "C"
  },
  {
    "question": "A Linux administrator has been tasked with installing the most recent versions of packages on a RPMbased OS. Which of the following commands will accomplish this task?",
    "choices": [
      "apt-get upgrade",
      "rpm -a",
      "yum updateinfo",
      "dnf update  E. yum check-update"
    ],
    "answer": "D"
  },
  {
    "question": "A Linux administrator needs to expand a volume group using a new disk. Which of the following options presents the correct sequence of commands to accomplish the task?",
    "choices": [
      "partprobe  vgcreate  lvextend",
      "lvcreate  tribalsent@yahoo.com 04 Jul 2025 fdisk  partprobe",
      "fdisk  partprobe  mkfs",
      "fdisk  pvcreate  vgextend"
    ],
    "answer": "D"
  },
  {
    "question": "Which of the following directories is the mount point in a UEFI system?",
    "choices": [
      "/sys/efi",
      "/boot/efi",
      "/efi",
      "/etc/efi"
    ],
    "answer": "B"
  },
  {
    "question": "A Linux administrator copied a Git repository locally, created a feature branch, and committed some changes to the feature branch. Which of the following Git actions should the Linux administrator use to publish the changes to the main branch of the remote repository?",
    "choices": [
      "rebase",
      "tag",
      "commit",
      "push"
    ],
    "answer": "D"
  },
  {
    "question": "A Linux administrator needs to obtain a list of all volumes that are part of a volume group. Which of the following commands should the administrator use to accomplish this task?",
    "choices": [
      "vgs",
      "lvs",
      "fdisk -1",
      "pvs"
    ],
    "answer": "B"
  },
  {
    "question": "A Linux administrator is adding a new configuration file to a Git repository. Which of the following describes the correct order of Git commands to accomplish the task successfully?",
    "choices": [
      "pull -> push -> add -> checkout",
      "pull -> add -> commit -> push",
      "checkout -> push -> add -> pull",
      "pull -> add -> push -> commit"
    ],
    "answer": "B"
  },
  {
    "question": "A systems administrator is tasked with mounting a USB drive on a system. The USB drive has a single partition, and it has been mapped by the system to the device /dev/sdb. Which of the following commands will mount the USB to /media/usb?",
    "choices": [
      "mount /dev/sdb1 /media/usb",
      "mount /dev/sdb0 /media/usb",
      "mount /dev/sdb /media/usb",
      "mount -t usb /dev/sdb1 /media/usb"
    ],
    "answer": "A"
  },
  {
    "question": "A developer reported an incident involving the application configuration file /etc/httpd/conf/httpd.conf that is missing from the server. Which of the following identifies the RPM package that installed the configuration file?",
    "choices": [
      "rpm -qf /etc/httpd/conf/httpd.conf",
      "rpm -ql /etc/httpd/conf/httpd.conf",
      "rpm \u201dquery /etc/httpd/conf/httpd.conf",
      "rpm -q /etc/httpd/conf/httpd.conf"
    ],
    "answer": "A"
  },
  {
    "question": "Joe, a user, is unable to log in to the Linux system Given the following output: Which of the following command would resolve the issue?",
    "choices": [
      "usermod -s /bin/bash joe",
      "pam_tally2 -u joe -r",
      "passwd -u joe",
      "chage -E 90 joe"
    ],
    "answer": "B"
  },
  {
    "question": "A cloud engineer needs to launch a container named web-01 in background mode. Which of the following commands will accomplish this task''",
    "choices": [
      "docker builder -f \u201dname web-01 httpd",
      "docker load --name web-01 httpd",
      "docker ps -a --name web-01 httpd",
      "docker run -d --name web-01 httpd"
    ],
    "answer": "D"
  },
  {
    "question": "Which of the following tools is BEST suited to orchestrate a large number of containers across many different servers?",
    "choices": [
      "Kubernetes",
      "Ansible",
      "Podman",
      "Terraform"
    ],
    "answer": "A"
  },
  {
    "question": "Which of the following enables administrators to configure and enforce MFA on a Linux system?",
    "choices": [
      "Kerberos",
      "SELinux",
      "PAM",
      "PKI"
    ],
    "answer": "C"
  },
  {
    "question": "A systems administrator is tasked with creating an Ansible playbook to automate the installation of patches on several Linux systems. In which of the following languages should the playbook be written?",
    "choices": [
      "SQL",
      "YAML",
      "HTML",
      "JSON"
    ],
    "answer": "B"
  },
  {
    "question": "A Linux administrator is providing a new Nginx image from the registry to local cache. Which of the following commands would allow this to happen?",
    "choices": [
      "docker pull nginx",
      "docker attach nginx",
      "docker commit nginx",
      "docker import nginx"
    ],
    "answer": "A"
  },
  {
    "question": "In which of the following filesystems are system logs commonly stored?",
    "choices": [
      "/var",
      "/tmp",
      "/etc",
      "/opt"
    ],
    "answer": "A"
  },
  {
    "question": "Which of the following data structures is written in JSON? A) B) C) D)",
    "choices": [
      "Option A  tribalsent@yahoo.com 04 Jul 2025",
      "Option B",
      "Option C",
      "Option D"
    ],
    "answer": "C"
  },
  {
    "question": "A Linux engineer needs to download a ZIP file and wants to set the nice of value to -10 for this new process. Which of the following commands will help to accomplish the task?",
    "choices": [
      "$ nice -v -10 wget https://foo.com/installation.zip",
      "$ renice -v -10 wget https://foo.com/installation.2ip",
      "$ renice -10 wget https://foo.com/installation.zip",
      "$ nice -10 wget https://foo.com/installation.zip"
    ],
    "answer": "D"
  },
  {
    "question": "A Linux systems administrator needs to copy files and directories from Server A to Server B. Which of the following commands can be used for this purpose? (Select TWO)",
    "choices": [
      "rsyslog",
      "cp",
      "rsync",
      "reposync  E. scp  F. ssh"
    ],
    "answer": "C"
  },
  {
    "question": "After installing a new version of a package, a systems administrator notices a new version of the corresponding, service file was Installed In order to use the new version of the, service file, which of the following commands must be Issued FIRST?",
    "choices": [
      "systemct1 status",
      "systemct1 stop  tribalsent@yahoo.com 04 Jul 2025",
      "systemct1 reinstall",
      "systemct1 daemon-reload"
    ],
    "answer": "D"
  },
  {
    "question": "An administrator recently updated the BIND software package and would like to review the default configuration that shipped with this version. Which of the following files should the administrator review?",
    "choices": [
      "/etc/named.conf.rpmnew",
      "/etc/named.conf.rpmsave",
      "/etc/named.conf",
      "/etc/bind/bind.conf"
    ],
    "answer": "A"
  },
  {
    "question": "In order to copy data from another VLAN, a systems administrator wants to temporarily assign IP address 10.0.6 5 to the newly added network interface enp1s0f1. Which of the following commands should the administrator run to achieve the goal?",
    "choices": [
      "ip addr add 10.0.6.5 dev enpls0f1",
      "echo 'IPV4_ADDRESS=10.0.6.5' > /etc/sysconfig/network-scripts/ifcfg-enplsOfl",
      "ifconfig 10.0.6.5 enpsIs0f1",
      "nmcli conn add lpv4.address-10.0.6.5 ifname enpls0f1"
    ],
    "answer": "A"
  },
  {
    "question": "The security team has identified a web service that is running with elevated privileges A Linux administrator is working to change the systemd service file to meet security compliance standards. Given the following output:  Which of the following remediation steps will prevent the web service from running as a privileged user?",
    "choices": [
      "Removing the ExecStarWusr/sbin/webserver -D SOPTIONS from the service file",
      "Updating the Environment File line in the [Service] section to/home/webservice/config",
      "Adding the User-webservice to the [Service] section of the service file",
      "Changing the:nulti-user.target in the [Install] section to basic.target"
    ],
    "answer": "C"
  },
  {
    "question": "A Linux engineer receives reports that files created within a certain group are being modified by users who are not group members. The engineer wants to reconfigure the server so that only file owners and group members can modify new files by default. Which of the following commands would accomplish this task?",
    "choices": [
      "chmod 775",
      "umask. 002",
      "chactr -Rv",
      "chown -cf"
    ],
    "answer": "B"
  },
  {
    "question": "A Linux administrator needs to connect securely to a remote server in order to install application software. Which of the following commands would allow this connection?",
    "choices": [
      "scp 'ABC-key.pem' root@10.0.0.1",
      "sftp rooteiO.0.0.1",
      "telnet 10.0.0.1 80",
      "ssh -i 'ABC-key.pem' root@10.0.0.1  E. sftp 'ABC-key.pem' root@10.0.0.1"
    ],
    "answer": "D"
  },
  {
    "question": "A Linux administrator rebooted a server. Users then reported some of their files were missing. After doing some troubleshooting, the administrator found one of the filesystems was missing. The filesystem was not listed in /etc/f stab and might have been mounted manually by someone prior to reboot. Which of the following would prevent this issue from reoccurring in the future?",
    "choices": [
      "Sync the mount units.",
      "Mount the filesystem manually.",
      "Create a mount unit and enable it to be started at boot.",
      "Remount all the missing filesystems"
    ],
    "answer": "C"
  },
  {
    "question": "A systems administrator is encountering performance issues. The administrator runs 3 commands with the following output The Linux server has the following system properties CPU: 4 vCPU Memory: 50GB Which of the following accurately describes this situation?",
    "choices": [
      "The system is under CPU pressure and will require additional vCPUs",
      "The system has been running for over a year and requires a reboot.",
      "Too many users are currently logged in to the system",
      "The system requires more memory"
    ],
    "answer": "A"
  },
  {
    "question": "A Linux administrator has logged in to a server for the first time and needs to know which services are allowed through the firewall. Which of the following options will return the results for which the administrator is looking?",
    "choices": [
      "firewall-cmd \u201dget-services",
      "firewall-cmd \u201dcheck-config",
      "firewall-cmd \u201dlist-services",
      "systemct1 status firewalld"
    ],
    "answer": "C"
  },
  {
    "question": "While inspecting a recently compromised Linux system, the administrator identified a number of processes that should not have been running: Which of the following commands should the administrator use to terminate all of the identified processes?",
    "choices": [
      "pkill -9 -f 'upload*.sh'",
      "kill -9 'upload*.sh'",
      "killall -9 -upload*.sh'",
      "skill -9 'upload*.sh'"
    ],
    "answer": "A"
  },
  {
    "question": "Which of the following commands is used to configure the default permissions for new files?",
    "choices": [
      "setenforce  tribalsent@yahoo.com 04 Jul 2025",
      "sudo",
      "umask",
      "chmod"
    ],
    "answer": "C"
  },
  {
    "question": "A Linux administrator has set up a new DNS forwarder and is configuring all internal servers to use the new forwarder to look up external DNS requests. The administrator needs to modify the firewall on the server for the DNS forwarder to allow the internal servers to communicate to it and make the changes persistent between server reboots. Which of the following commands should be run on the DNS forwarder server to accomplish this task?",
    "choices": [
      "ufw allow out dns",
      "systemct1 reload firewalld",
      "iptables -A OUTPUT -p udp -ra udp -dport 53 -j ACCEPT",
      "flrewall-cmd --zone-public --add-port-53/udp --permanent    tribalsent@yahoo.com 04 Jul 2025"
    ],
    "answer": "D"
  },
  {
    "question": "A systems administrator has been unable to terminate a process. Which of the following should the administrator use to forcibly stop the process?",
    "choices": [
      "kill -1",
      "kill -3",
      "kill -15",
      "kill -HUP  E. kill -TERM    Answer: E    Explanation:   The administrator should use the command kill -TERM to forcibly stop the process. The kill command  tribalsent@yahoo.com 04 Jul 2025 is a tool for sending signals to processes on Linux systems. Signals are messages that inform the  processes about certain events and actions. The processes can react to the signals by performing  predefined or user-defined actions, such as terminating, suspending, resuming, or ignoring. The -  TERM option specifies the signal name or number that the kill command should send. The TERM  signal, which stands for terminate, is the default signal that the kill command sends if no option is  specified. The TERM signal requests the process to terminate gracefully, by closing any open files,  releasing any resources, and performing any cleanup tasks. However, if the process does not respond  to the TERM signal, the kill command can send a stronger signal, such as the KILL signal, which forces  the process to terminate immediately, without any cleanup. The administrator should use the  command kill -TERM to forcibly stop the process. This is the correct answer to the question. The  other options are incorrect because they either do not terminate the process (kill -1 or kill -3) or do  not terminate the process forcibly (kill -15 or kill -HUP). Reference: CompTIA Linux+ (XK0-005)  Certification Study Guide, Chapter 14: Managing Processes, page 431.  QUESTION 161  A systems administrator is compiling a report containing information about processes that are  listening on the network ports of a Linux server. Which of the following commands will allow the  administrator to obtain the needed information?    A. ss -pint  B. tcpdump -nL  C. netstat -pn  D. lsof -It"
    ],
    "answer": "A"
  },
  {
    "question": "User1 is a member of the accounting group. Members of this group need to be able to execute but not make changes to a script maintained by User2. The script should not be accessible to other users or groups. Which of the following will give proper access to the script?",
    "choices": [
      "chown user2:accounting script.sh  chmod 750 script.sh",
      "chown user1:accounting script.sh  chmod 777 script.sh",
      "chown accounting:user1 script.sh  chmod 057 script.sh",
      "chown user2:accounting script.sh  chmod u+x script.sh"
    ],
    "answer": "A"
  },
  {
    "question": "A systems administrator needs to verify whether the built container has the app.go file in its root directory. Which of the following can the administrator use to verify the root directory has this file?",
    "choices": [
      "docker image inspect",
      "docker container inspect",
      "docker exec <container_name> ls",
      "docker ps <container_name>"
    ],
    "answer": "C"
  },
  {
    "question": "A Linux administrator is reviewing changes to a configuration file that includes the following section:  The Linux administrator is trying to select the appropriate syntax formatter to correct any issues with the configuration file. Which of the following should the syntax formatter support to meet this goal?",
    "choices": [
      "Markdown",
      "XML",
      "YAML",
      "JSON"
    ],
    "answer": "C"
  },
  {
    "question": "A systems administrator is investigating an issue in which one of the servers is not booting up properly. The journalctl entries show the following:  Which of the following will allow the administrator to boot the Linux system to normal mode quickly?",
    "choices": [
      "Comment out the /opt/app filesystem in /etc/fstab and reboot.",
      "Reformat the /opt/app filesystem and reboot.",
      "Perform filesystem checks on local filesystems and reboot.",
      "Trigger a filesystem relabel and reboot."
    ],
    "answer": "A"
  },
  {
    "question": "A Linux systems administrator receives reports from various users that an application hosted on a server has stopped responding at similar times for several days in a row. The administrator logs in to the system and obtains the following output: Output 1: Output 2: Output 3: Which of the following should the administrator do to provide the BEST solution for the reported issue?",
    "choices": [
      "Configure memory allocation policies during business hours and prevent the Java process from  going into a zombie state while the server is idle.",
      "Configure a different nice value for the Java process to allow for more users and prevent the Java  process from restarting during business hours.",
      "Configure more CPU cores to allow for the server to allocate more processing and prevent the Java  process from consuming all of the available resources.",
      "Configure the swap space to allow for spikes in usage during peak hours and prevent the Java  process from stopping due to a lack of memory."
    ],
    "answer": "D"
  },
  {
    "question": "A Linux administrator found many containers in an exited state. Which of the following commands will allow the administrator to clean up the containers in an exited state?",
    "choices": [
      "docker rm --all",
      "docker rm $(docker ps -aq)",
      "docker images prune *",
      "docker rm --state exited"
    ],
    "answer": "B"
  },
  {
    "question": "A Linux administrator reviews a set of log output files and needs to identify files that contain any occurrence of the word denied. All log files containing entries in uppercase or lowercase letters should be included in the list. Which of the following commands should the administrator use to accomplish this task?",
    "choices": [
      "find . -type f -print | xrags grep -ln denied",
      "find . -type f -print | xrags grep -nv denied",
      "find . -type f -print | xrags grep -wL denied",
      "find . -type f -print | xrags grep -li denied"
    ],
    "answer": "D"
  },
  {
    "question": "A Linux administrator is installing a web server and needs to check whether web traffic has already been allowed through the firewall. Which of the following commands should the administrator use to accomplish this task?",
    "choices": [
      "firewalld query-service-http",
      "firewall-cmd --check-service http",
      "firewall-cmd --query-service http",
      "firewalld --check-service http"
    ],
    "answer": "C"
  },
  {
    "question": "Joe, a user, is unable to log in to the Linux system. Given the following output:  Which of the following commands would resolve the issue?",
    "choices": [
      "usermod -s /bin/bash joe",
      "pam_tally2 -u joe -r",
      "passwd -u joe",
      "chage -E 90 joe"
    ],
    "answer": "B"
  },
  {
    "question": "Users have been unable to save documents to /home/tmp/temp and have been receiving the following error: Path not found  A junior technician checks the locations and sees that /home/tmp/tempa was accidentally created instead of /home/tmp/temp. Which of the following commands should the technician use to fix this issue?",
    "choices": [
      "cp /home/tmp/tempa /home/tmp/temp",
      "mv /home/tmp/tempa /home/tmp/temp",
      "cd /temp/tmp/tempa",
      "ls /home/tmp/tempa"
    ],
    "answer": "B"
  },
  {
    "question": "A database administrator requested the installation of a custom database on one of the servers. Which of the following should the Linux administrator configure so the requested packages can be installed?\n<pre>\nOutput 1:\n[Application Java Stack Info]\n\nOutput 2:\n[Memory spike logs during same time windows]\n\nOutput 3:\n[System logs showing process killed due to OOM]\n</pre>",
    "choices": [
      "/etc/yum.conf",
      "/etc/ssh/sshd.conf",
      "/etc/yum.repos.d/db.repo",
      "/etc/resolv.conf"
    ],
    "answer": "C"
  },
  {
    "question": "At what point is the Internal Certificate Authority (ICA) created?",
    "choices": [
      "During the primary Security Management Server installation process.",
      "Upon creation of a certificate.",
      "When an administrator decides to create one.",
      "When an administrator initially logs into SmartConsole."
    ],
    "answer": "A"
  },
  {
    "question": "Rugged appliances are small appliances with ruggedized hardware and like Quantum Spark appliance they use which operating system?",
    "choices": [
      "Centos Linux",
      "Gaia embedded",
      "Gaia",
      "Red Hat Enterprise Linux version 5  tribalsent@yahoo.com 04 Jul 2025"
    ],
    "answer": "B"
  },
  {
    "question": "Using AD Query, the security gateway connections to the Active Directory Domain Controllers using what protocol?",
    "choices": [
      "Windows Management Instrumentation (WMI)",
      "Hypertext Transfer Protocol Secure (HTTPS)",
      "Lightweight Directory Access Protocol (LDAP)",
      "Remote Desktop Protocol (RDP)"
    ],
    "answer": "C"
  },
  {
    "question": "What is the main objective when using Application Control?",
    "choices": [
      "To filter out specific content.",
      "To assist the firewall blade with handling traffic.  tribalsent@yahoo.com 04 Jul 2025",
      "To see what users are doing.",
      "Ensure security and privacy of information."
    ],
    "answer": "D"
  },
  {
    "question": "During a security scan, the password of an SSH key file appeared to be too weak and was cracked. Which of the following commands would allow a user to choose a stronger password and set it on the existing SSH key file?",
    "choices": [
      "passwd",
      "ssh",
      "ssh-keygen",
      "pwgen"
    ],
    "answer": "C"
  },
  {
    "question": "A Linux systems administrator is troubleshooting an I/O latency on a single CPU server. The administrator runs a top command and receives the following output: %Cpu(s): 0.2 us, 33.1 sy, 0.0 ni, 0.0 id, 52.4 wa, 0.0 hi, 0.2 si, 0.0 st Which of the following is correct based on the output received from the exe-cuted command?",
    "choices": [
      "The server's CPU is taking too long to process users' requests.",
      "The server's CPU shows a high idle-time value.",
      "The server's CPU is spending too much time waiting for data inputs.",
      "The server's CPU value for the time spent on system processes is low."
    ],
    "answer": "C"
  },
  {
    "question": "Which of the following can be used as a secure way to access a remote termi-nal?",
    "choices": [
      "TFTP",
      "SSH",
      "SCP",
      "SFTP"
    ],
    "answer": "B"
  },
  {
    "question": "A user reported issues when trying to log in to a Linux server. The following outputs were received: Given the outputs above. which of the following is the reason the user is una-ble to log in to the server?",
    "choices": [
      "User1 needs to set a long password.",
      "User1 is in the incorrect group.",
      "The user1 shell assignment incorrect.",
      "The user1 password is expired.  tribalsent@yahoo.com 04 Jul 2025"
    ],
    "answer": "D"
  },
  {
    "question": "A systems administrator wants to list all local accounts in which the UID is greater than 500. Which of the following commands will give the correct output?",
    "choices": [
      "find /etc/passwd \u201dsize +500",
      "cut \u201dd: fl / etc/ passwd > 500",
      "awk -F: \u02dc$3 > 500 {print $1}' /etc/passwd",
      "sed '/UID/' /etc/passwd < 500"
    ],
    "answer": "C"
  },
  {
    "question": "A Linux administrator has physically added a new RAID adapter to a system. Which of the following commands should the Linux administrator run to confirm that the device has been recognized? (Select TWO).",
    "choices": [
      "rmmod",
      "Is -11 /etc",
      "Ishw \u201dclass disk",
      "pvdisplay  E. rmdir /dev  F. dmesg"
    ],
    "answer": "C"
  },
  {
    "question": "A user is attempting to log in to a Linux server that has Kerberos SSO ena-bled. Which of the following commands should the user run to authenticate and then show the ticket grants? (Select TWO).",
    "choices": [
      "kinit",
      "klist",
      "kexec",
      "kioad  E. pkexec  F. realm"
    ],
    "answer": "A"
  },
  {
    "question": "After starting an Apache web server, the administrator receives the following error: Apr 23 localhost.localdomain httpd 4618] : (98) Address already in use: AH00072: make_sock: could not bind to address [: :]80 Which of the following commands should the administrator use to further trou-bleshoot this issue?",
    "choices": [
      "Ss",
      "Ip",
      "Dig",
      "Nc"
    ],
    "answer": "A"
  },
  {
    "question": "A systems administrator detected corruption in the /data filesystem. Given the following output:  Which of the following commands can the administrator use to best address this issue?",
    "choices": [
      "umount /data  mkfs . xfs /dev/sclcl  mount /data",
      "umount /data  xfs repair /dev/ sdcl  mount /data  tribalsent@yahoo.com 04 Jul 2025",
      "umount /data  fsck /dev/ sdcl  mount / data",
      "umount /data  pvs /dev/sdcl  mount /data"
    ],
    "answer": "B"
  },
  {
    "question": "A Linux administrator is configuring a two-node cluster and needs to be able to connect the nodes to each other using SSH keys from the root account. Which of the following commands will accomplish this task?",
    "choices": [
      "[root@nodea ssh \u201di ~/ . ssh/\u00c2\u00b1d rsa root@nodeb",
      "[root@nodea scp -i . ssh/id rsa root@nodeb",
      "[root@nodea ssh\u201dcopy-id \u201di .ssh/id rsa root@nodeb",
      "[root@nodea # ssh add -c ~/ . ssh/id rsa root@nodeb  E. [root@nodea # ssh add -c ~/. ssh/id rsa root@nodeb"
    ],
    "answer": "C"
  },
  {
    "question": "A systems administrator is enabling LUKS on a USB storage device with an ext4 filesystem format. The administrator runs dmesg and notices the following output: Given this scenario, which of the following should the administrator perform to meet these requirements? (Select three).",
    "choices": [
      "gpg /dev/sdcl",
      "pvcreate /dev/sdc",
      "mkfs . ext4 /dev/mapper/LUKSCJ001 - L ENCRYPTED",
      "umount / dev/ sdc  E. fdisk /dev/sdc  F. mkfs . vfat /dev/mapper/LUKS0001 \u201d L ENCRYPTED  G. wipefs \u201da/dev/sdbl  H. cryptsetup IuksFormat /dev/ sdcl"
    ],
    "answer": "C"
  },
  {
    "question": "Which of the following actions are considered good security practices when hardening a Linux server? (Select two).",
    "choices": [
      "Renaming the root account to something else",
      "Removing unnecessary packages",
      "Changing the default shell to /bin/csh",
      "Disabling public key authentication  E. Disabling the SSH root login possibility  F. Changing the permissions on the root filesystem to 600"
    ],
    "answer": "B"
  },
  {
    "question": "A new disk was presented to a server as /dev/ sdd. The systems administrator needs to check if a partition table is on that disk. Which of the following commands can show this information?",
    "choices": [
      "Isscsi",
      "fdisk",
      "blkid",
      "partprobe"
    ],
    "answer": "B"
  },
  {
    "question": "A systems administrator wants to check for running containers. Which of the following commands can be used to show this information?",
    "choices": [
      "docker pull",
      "docker stats",
      "docker ps",
      "docker list"
    ],
    "answer": "C"
  },
  {
    "question": "A systems administrator is installing various software packages using a pack-age manager. Which of the following commands would the administrator use on the Linux server to install the package?",
    "choices": [
      "winget",
      "softwareupdate",
      "yum-config",
      "apt    tribalsent@yahoo.com 04 Jul 2025"
    ],
    "answer": "D"
  },
  {
    "question": "A user created the following script file: # ! /bin/bash # FILENAME: /home/user/ script . sh echo 'hello world' exit 1 However, when the user tried to run the script file using the command 'script . sh, an error returned indicating permission was denied. Which of the follow-ing should the user execute in order for the script to run properly?",
    "choices": [
      "chmod u+x /home/user/script . sh",
      "chmod 600 /home/user/script . sh",
      "chmod /home/user/script . sh",
      "chmod 0+r /horne/user/script. sh"
    ],
    "answer": "A"
  },
  {
    "question": "A systems administrator checked out the code from the repository, created a new branch, made changes to the code, and then updated the main branch. The systems administrator wants to ensure that the Terraform state files do not appear in the main branch. Which of following should the administrator use to meet this requirement?",
    "choices": [
      "clone",
      "gitxgnore  tribalsent@yahoo.com 04 Jul 2025",
      "get",
      ".ssh"
    ],
    "answer": "B"
  },
  {
    "question": "A junior administrator updated the PostgreSQL service unit file per the data-base administrator's recommendation. The service has been restarted, but changes have not been applied. Which of the following should the administrator run for the changes to take effect?",
    "choices": [
      "Systemct1 get\u201ddefault",
      "systemct1 daemon\u201dreload",
      "systemct1 enable postgresq1",
      "systemct1 mask postgresq1"
    ],
    "answer": "B"
  },
  {
    "question": "A developer needs to launch an Nginx image container, name it Web001, and ex-pose port 8080 externally while mapping to port 80 inside the container. Which of the following commands will  accomplish this task?",
    "choices": [
      "docker exec \u201dit -p 8080: 80 \u201d\u201dname Web001 nginx",
      "docker load -it -p 8080:80 \u201d\u201dname Web001 nginx",
      "docker run -it -P 8080:80 \u201d\u201dname Web001 nginx",
      "docker pull -it -p 8080:80 \u201dname Web00l nginx"
    ],
    "answer": "C"
  },
  {
    "question": "A junior developer is unable to access an application server and receives the following output:  The systems administrator investigates the issue and receives the following output: Which of the following commands will help unlock the account?",
    "choices": [
      "Pam_tally2 --user=dev2 \u201d-quiet",
      "pam_ tally2 --user=dev2",
      "pam_tally2 -\u201cuser+dev2 \u201d-quiet",
      "pam_tally2 --user=dev2 \u201d-reset"
    ],
    "answer": "D"
  },
  {
    "question": "A systems administrator wants to delete app . conf from a Git repository. Which of the following commands will delete the file?",
    "choices": [
      "git tag app. conf",
      "git commit app . conf",
      "git checkout app . conf",
      "git rm app. conf"
    ],
    "answer": "D"
  },
  {
    "question": "A senior Linux administrator has created several scripts that will be used to install common system applications. These scripts are published to a reposito-ry to share with the systems team. A junior Linux administrator needs to re-trieve the scripts and make them available on a local workstation. Which of the following Git commands should the junior Linux administrator use to accom-plish this task?",
    "choices": [
      "fetch",
      "checkout",
      "clone",
      "branch  tribalsent@yahoo.com 04 Jul 2025"
    ],
    "answer": "C"
  },
  {
    "question": "A DevOps engineer wants to allow the same Kubernetes container configurations to be deployed in development, testing, and production environments. A key requirement is that the containers should be configured so that developers do not have to statically configure custom, environment-specific locations. Which of the following should the engineer use to meet this requirement?",
    "choices": [
      "Custom scheduler",
      "Node affinity",
      "Overlay network",
      "Ambassador container"
    ],
    "answer": "D"
  },
  {
    "question": "Due to performance issues on a server, a Linux administrator needs to termi-nate an unresponsive process. Which of the following commands should the  administrator use to terminate the process immediately without waiting for a graceful shutdown?",
    "choices": [
      "kill -SIGKILL 5545",
      "kill -SIGTERM 5545",
      "kill -SIGHUP 5545",
      "kill -SIGINT 5545"
    ],
    "answer": "A"
  },
  {
    "question": "A systems administrator intends to use a UI-JID to mount a new partition per-manently on a Linux system. Which of the following commands can the adminis-trator run to obtain information about the UUlDs of all disks attached to a Linux system?",
    "choices": [
      "fcstat",
      "blkid",
      "dmsetup",
      "Isscsi"
    ],
    "answer": "B"
  },
  {
    "question": "As part of the requirements for installing a new application, the swappiness parameter needs to be changed to O. This change needs to persist across re-boots and be applied immediately. A Linux systems administrator is performing this change. Which of the following steps should the administrator complete to accomplish this task?",
    "choices": [
      "echo 'vm. swappiness\u201d()' >> /etc/sysctl . conf && sysctl \u201dp",
      "echo 'vrn. >> / proc/meminfo && sysctl \u201da",
      "sysctl \u201dv >> / proc/meminfo & & echo 'vm. swapiness=0'",
      "sysctl \u201dh 'vm. swapiness\u201dO' && echo / etc/vmswapiness"
    ],
    "answer": "A"
  },
  {
    "question": "An administrator would like to mirror the website files on the primary web server, www1, to the backup web server, www2. Which of the following commands should the administrator use to most efficiently accomplish this task?",
    "choices": [
      "[wwwl ] rsync \u201da \u201de ssh /var/www/html/ user1@www2 : /var/www/html",
      "[ wwwl ] scp \u201dr /var/www/html user1@www2 : / var/www/html",
      "[www2 ] cd /var/www/html; wget \u201dm http: //wwwl/",
      "[wwwl ] cd /var/www/html && tar cvf \u201d"
    ],
    "answer": "A"
  },
  {
    "question": "An administrator needs to get network information from a group of statically assigned workstations before they are reconnected to the network. Which of the following should the administrator use to obtain this information?",
    "choices": [
      "ip show",
      "ifcfg \u201da",
      "ifcfg \u201ds",
      "i fname \u201ds"
    ],
    "answer": "B"
  },
  {
    "question": "A developer wants to ensure that all files and folders created inside a shared folder named /GroupOODEV inherit the group name of the parent folder. Which of the following commands will help achieve this goal?",
    "choices": [
      "chmod g+X / GroupOODEV/",
      "chmod g+W / GroupOODEV/",
      "chmod g+r / GroupOODEV/",
      "chmod g+s / GroupOODEV/"
    ],
    "answer": "D"
  },
  {
    "question": "Ann, a security administrator, is performing home directory audits on a Linux server. Ann issues the su Joe command and then issues the Is command. The output displays files that reside in Ann's home directory instead of Joe's. Which of the following represents the command Ann should have issued in order to list Joe's files?",
    "choices": [
      "su - Joe",
      "sudo Joe",
      "visudo Joe",
      "pkexec joe"
    ],
    "answer": "A"
  },
  {
    "question": "The applications team is reporting issues when trying to access the web service hosted in a Linux  system. The Linux systems administrator is reviewing the following outputs: Output 1: * httpd.service = The Apache HTTPD Server Loaded: loaded (/usr/lib/systemd/system/httpd.service; disabled; vendor preset: disabled) Active: inactive (dead) Docs: man:httpd(8) man:apachectl(8) Output 2: 16:51:16 up 28 min, 1 user, load average: 0.00, 0.00, 0.07 Which of the following statements best describe the root cause? (Select two).",
    "choices": [
      "The httpd service is currently started.",
      "The httpd service is enabled to auto start at boot time, but it failed to start.",
      "The httpd service was manually stopped.",
      "The httpd service is not enabled to auto start at boot time. E. The httpd service runs without problems. F. The httpd service did not start during the last server reboot."
    ],
    "answer": "C"
  },
  {
    "question": "A user is unable to remotely log on to a server using the server name server1 and port 22. The Linux engineer troubleshoots the issue and gathers the following information: Which of the following is most likely causing the issue?",
    "choices": [
      "server 1 is not in the DNS.",
      "sshd is running on a non-standard port.",
      "sshd is not an active service.",
      "serverl is using an incorrect IP address. tribalsent@yahoo.com 04 Jul 2025"
    ],
    "answer": "B"
  },
  {
    "question": "A systems administrator wants to upgrade /bin/ someapp to a new version, but the administrator does not know the package name. Which of the following will show the RPM package name that provides that binary file?",
    "choices": [
      "rpm \u201dqf /bin/ someapp",
      "rpm \u201dVv / bin/ someapp",
      "rpm - P / bin/ some app",
      "rpm \u201di / bin/ someapp"
    ],
    "answer": "A"
  },
  {
    "question": "Which of the following specifications is used to perform disk encryption in a Linux system?",
    "choices": [
      "LUKS",
      "TLS",
      "SSL",
      "NFS    tribalsent@yahoo.com 04 Jul 2025"
    ],
    "answer": "A"
  },
  {
    "question": "An engineer needs to insert a character at the end of the current line in the vi text editor. Which of the following will allow the engineer to complete this task?",
    "choices": [
      "p",
      "r",
      "bb",
      "A  E. i"
    ],
    "answer": "D"
  },
  {
    "question": "An administrator started a long-running process in the foreground that needs to continue without interruption. Which of the following keystrokes should the administrator use to continue running the process in the background?",
    "choices": [
      "<Ctrl+z> bg",
      "<Ctrl+d> bg",
      "<Ctrl+b> jobs -1",
      "<Ctrl+h> bg &"
    ],
    "answer": "A"
  },
  {
    "question": "Which of the following would significantly help to reduce data loss if more than one drive fails at the same time? \n<pre>\nOutput 1:\n* httpd.service = The Apache HTTPD Server\nLoaded: loaded (/usr/lib/systemd/system/httpd.service; disabled; vendor preset: disabled)\nActive: inactive (dead)\nDocs: man:httpd(8) man:apachectl(8)\n\nOutput 2:\n16:51:16 up 28 min, 1 user, load average: 0.00, 0.00, 0.07\n</pre>",
    "choices": [
      "Server clustering",
      "Load balancing",
      "RAID",
      "VDI"
    ],
    "answer": "C"
  },
  {
    "question": "A systems administrator is investigating a service that is not starting up. Given the following information: Which of the following systemd commands should the administrator use in order to obtain more details about the failing service?",
    "choices": [
      "systemct1 analyze network",
      "systemct1 info network",
      "sysctl -a network",
      "journalctl -xu network  tribalsent@yahoo.com 04 Jul 2025"
    ],
    "answer": "D"
  },
  {
    "question": "A systems administrator is adding a Linux-based server and removing a Windows-based server from a cloud-based environment. The changes need to be validated before they are applied to the cloudbased environment. Which of the following tools should be used to meet this requirement?",
    "choices": [
      "Ansible",
      "git clone",
      "git pull",
      "terraform plan"
    ],
    "answer": "D"
  },
  {
    "question": "A Linux administrator needs to create a symlink for /usr/local/bin/app-a, which was installed in /usr/local/share/appa. Which of the following commands should the administrator use?",
    "choices": [
      "In -s /usr/local/bin/app-a /usr/local/share/app-a",
      "mv -f /usr/local/share/app-a /usr/local/bin/app-a",
      "cp -f /usr/local/share/app-a /usr/local/bin/app-a",
      "rsync -a /usr/local/share/app-a /usr/local/bin/app-a"
    ],
    "answer": "A"
  },
  {
    "question": "The group named support is unable to make changes to the config file. An administrator is reviewing the permissions and sees the following:  S Is -1 config -rw-rw----. 1 root app 4682 02-15 11:25 config Which of the following should the administrator execute in order to give the support group access to modify the file while preserving the current ownership?",
    "choices": [
      "chown :support config",
      "setfacl -m g:support:rw- config",
      "chmod 664 config",
      "chmod g+s config"
    ],
    "answer": "C"
  },
  {
    "question": "A systems administrator receives reports that several virtual machines in a host are responding slower than expected. Upon further investigation, the administrator obtains the following output from one of the affected systems: Which of the following best explains the reported issue?",
    "choices": [
      "The physical host is running out of CPU resources, leading to insufficient CPU time being allocated  to virtual machines.",
      "The physical host has enough CPU cores, leading to users running more processes to compensate  for the slower response times.",
      "The virtual machine has enough CPU cycles, leading to the system use percentage being higher  than expected.",
      "The virtual machine is running out of CPU resources, leading to users experiencing longer  response times."
    ],
    "answer": "D"
  },
  {
    "question": "A cloud engineer wants to delete all unused networks that are not referenced by any container. Which of the following commands will achieve this goal?",
    "choices": [
      "docker network erase",
      "docker network clear",
      "docker network prune",
      "docker network rm"
    ],
    "answer": "C"
  },
  {
    "question": "A systems administrator wants to permit access temporarily to an application running on port 1234/TCP on a Linux server. Which of the following commands will permit this traffic?",
    "choices": [
      "firewall-cmd \u201dnew-service=1234/tcp",
      "firewall-cmd \u201dservice=1234 \u201dprotocol=tcp",
      "firewall-cmd \u201dadd\u201dport=1234/tcp",
      "firewall-cmd \u201dadd-whitelist-uid=1234"
    ],
    "answer": "C"
  },
  {
    "question": "The development team wants to prevent a file from being modified by all users in a Linux system, including the root account. Which of the following commands can be used to accomplish this objective?",
    "choices": [
      "chmod / app/conf/file",
      "setenforce / app/ conf/ file",
      "chattr +i /app/conf/file",
      "chmod 0000 /app/conf/file"
    ],
    "answer": "C"
  },
  {
    "question": "DRAG DROP A new drive was recently added to a Linux system. Using the environment and tokens provided, complete the following tasks: Create an appropriate device label. Format and create an ext4 file system on the new partition. The current working directory is /.  Answer:  Explanation: To create an appropriate device label, format and create an ext4 file system on the new partition, you can use the following commands: To create a GPT (GUID Partition Table) label on the new drive /dev/sdc, you can use the parted command with the -s option (for script mode), the device name (/dev/sdc), the mklabel command, and the label type (gpt). The command is: parted -s /dev/sdc mklabel gpt To create a primary partition of 10 GB on the new drive /dev/sdc, you can use the parted command with the -s option, the device name (/dev/sdc), the mkpart command, the partition type (primary), the file system type (ext4), and the start and end points of the partition (1 and 10G). The command is: parted -s /dev/sdc mkpart primary ext4 1 10G To format and create an ext4 file system on the new partition /dev/sdc1, you can use the mkfs command with the file system type (ext4) and the device name (/dev/sdc1). The command is: mkfs.ext4 /dev/sdc1 You can verify that the new partition and file system have been created by using the lsblk command, which will list all block devices and their properties.  QUESTION 223 An administrator would like to securely connect to a server and forward port 8080 on a local machine to port 80 on the server. Which of the following commands should the administrator use to satisfy both requirements?",
    "choices": [
      "ssh \u201dL 8080: localhost:80 admin@server",
      "ssh \u201dR 8080: localhost:80 admin@server",
      "ssh \u201dL 80 : localhost:8080 admin@server",
      "ssh \u201dR 80 : localhost:8080 admin@server"
    ],
    "answer": "A"
  },
  {
    "question": "The administrator comptia is not able to perform privileged functions on a newly deployed system. Given the following command outputs: Which of the following is the reason that the administrator is unable to perform the assigned duties?",
    "choices": [
      "The administrator needs a password reset.",
      "The administrator is not a part of the correct group.",
      "The administrator did not update the sudo database.",
      "The administrator's credentials need to be more complex."
    ],
    "answer": "B"
  },
  {
    "question": "A Linux administrator intends to start using KVM on a Linux server. Which of the following commands will allow the administrator to load the KVM module as well as any related dependencies?",
    "choices": [
      "modprobe kvm",
      "insmod kvm",
      "depmod kvm",
      "hotplug kvm"
    ],
    "answer": "A"
  },
  {
    "question": "A systems administrator received a request to change a user's credentials. Which of the following commands will grant the request?",
    "choices": [
      "sudo passwd",
      "sudo userde 1",
      "sudo chage",
      "sudo usermod"
    ],
    "answer": "A"
  },
  {
    "question": "Application code is stored in Git. Due to security concerns, the DevOps engineer does not want to keep a sensitive configuration file, app . conf, in the repository. Which of the following should the engineer do to prevent the file from being uploaded to the repository?",
    "choices": [
      "Run git exclude app. conf.",
      "Run git stash app. conf.",
      "Add app . conf to . exclude.",
      "Add app . conf to . gitignore."
    ],
    "answer": "D"
  },
  {
    "question": "A systems administrator is working on a security report from the Linux servers. Which of the following commands can the administrator use to display all the firewall rules applied to the Linux servers? (Select two).",
    "choices": [
      "ufw limit",
      "iptables \u201dF",
      "systemct1 status firewalld",
      "firewall\u201dcmd \u201d\u201d1ist\u201da11  E. ufw status  F. iptables \u201dA"
    ],
    "answer": "D"
  },
  {
    "question": "**INSTRUCTIONS:** Fill in the shell script below.\n\nAn administrator needs to make an application change via a script that must be run only in console mode. Which of the following best represents the sequence the administrator should execute to accomplish this task?\n\n<pre># /tmp/script.sh\nfind /var/log -maxdepth 1 -name '*.gz' -exec gzip {} \\;</pre>",
    "choices": [
      "systemct1 isolate multi-user.target  sh script.sh  systemct1 isolate graphical.target",
      "systemct1 isolate graphical.target  sh script.sh  systemct1 isolate multi-user.target",
      "sh script.sh  systemct1 isolate multi-user.target  systemct1 isolate graphical.target",
      "systemct1 isolate multi-user.target  systemct1 isolate graphical.target  sh script.sh"
    ],
    "answer": "A"
  },
  {
    "question": "An administrator created an initial Git repository and uploaded the first files. The administrator sees the following when listing the repository:  The administrator notices the file . DS STORE should not be included and deletes it from the online repository. Which of the following should the administrator run from the root of the local repository before the next commit to ensure the file is not uploaded again in future commits?",
    "choices": [
      "rm -f .DS STORE && git push",
      "git fetch && git checkout .DS STORE",
      "rm -f .DS STORE && git rebase origin main",
      "echo .DS STORE >> .gitignore"
    ],
    "answer": "D"
  },
  {
    "question": "Users are unable to create new files on the company's FTP server, and an administrator is troubleshooting the issue. The administrator runs the following commands: Which of the following is the cause of the issue based on the output above?",
    "choices": [
      "The users do not have the correct permissions to create files on the FTP server.",
      "The ftpusers filesystem does not have enough space.",
      "The inodes is at full capacity and would affect file creation for users.",
      "ftpusers is mounted as read only."
    ],
    "answer": "C"
  },
  {
    "question": "An administrator added the port 2222 for the SSH server on myhost and restarted the SSH server. The  administrator noticed issues during the startup of the service. Given the following outputs: Which of the following commands will fix the issue?",
    "choices": [
      "semanage port -a -t ssh_port_t -p tcp 2222",
      "chcon system_u:object_r:ssh_home_t /etc/ssh/*",
      "iptables -A INPUT -p tcp -- dport 2222 -j ACCEPT",
      "firewall-cmd -- zone=public -- add-port=2222/tcp"
    ],
    "answer": "A"
  },
  {
    "question": "A DevOps engineer is working on a local copy of a Git repository. The engineer would like to switch from the main branch to the staging branch but notices the staging branch does not exist. Which of the following Git commands should the engineer use to perform this task?",
    "choices": [
      "git branch \u201dm staging",
      "git commit \u201dm staging",
      "git status \u201db staging",
      "git checkout \u201db staging  tribalsent@yahoo.com 04 Jul 2025"
    ],
    "answer": "D"
  },
  {
    "question": "The group owner of the / home/ test directory would like to preserve all group permissions on files created in the directory. Which of the following commands should the group owner execute?",
    "choices": [
      "chmod g+s /home/test",
      "chgrp test /home/test",
      "chmod 777 /home/test  tribalsent@yahoo.com 04 Jul 2025",
      "chown \u201dhR test /home/test"
    ],
    "answer": "A"
  },
  {
    "question": "A systems engineer has deployed a new application server, but the server cannot communicate with  the backend database hostname. The engineer confirms that the application server can ping the database server's IP address. Which of the following is the most likely cause of the issue?",
    "choices": [
      "Incorrect DNS servers",
      "Unreachable default gateway",
      "Missing route configuration",
      "Misconfigured subnet mask"
    ],
    "answer": "A"
  },
  {
    "question": "A systems administrator is tasked with changing the default shell of a system account in order to disable iterative logins. Which of the following is the best option for the administrator to use as the new shell?",
    "choices": [
      "/sbin/nologin",
      "/bin/ sh",
      "/sbin/ setenforce",
      "/bin/bash"
    ],
    "answer": "A"
  },
  {
    "question": "An administrator needs to increase the system priority of a process with PID 2274. Which of the following commands should the administrator use to accomplish this task?",
    "choices": [
      "renice \u201dn \u201d15 2274",
      "nice -15 2274",
      "echo '\u201d15' > /proc/PID4/priority",
      "ps \u201def I grep 2274"
    ],
    "answer": "A"
  },
  {
    "question": "A junior systems administrator recently installed an HBA card in one of the servers that is deployed for a production environment. Which of the following commands can the administrator use to confirm on which server the card was installed?",
    "choices": [
      "lspci | egrep 'hba| fibr'",
      "lspci | zgrep 'hba | fibr'",
      "lspci | pgrep 'hba| fibr'",
      "lspci | 'hba | fibr'"
    ],
    "answer": "A"
  },
  {
    "question": "Users in the human resources department are trying to access files in a newly created directory. Which of the following commands will allow the users access to the files?",
    "choices": [
      "chattr",
      "chgrp",
      "chage",
      "chcon"
    ],
    "answer": "B"
  },
  {
    "question": "A User on a Linux workstation needs to remotely start an application on a Linux server and then forward the graphical display of that application back to the Linux workstation. Which of the following would enable the user to perform this action?",
    "choices": [
      "ssh -X user@server application",
      "ssh -y user@server application",
      "ssh user@server application",
      "ssh -D user@server application"
    ],
    "answer": "A"
  },
  {
    "question": "A Linux administrator is creating a new sudo profile for the accounting user. Which of the following should be added by the administrator to the sudo configuration file so that the accounting user can run / opt/ acc/ report as root?",
    "choices": [
      "accounting localhost=/opt/acc/report",
      "accounting ALL=/opt/acc/report",
      "%accounting ALL=(ALL) NOPASSWD: /opt/acc/report",
      "accounting /opt/acc/report= (ALL) NOPASSWD: ALL"
    ],
    "answer": "C"
  },
  {
    "question": "A systems administrator is trying to track down a rogue process that has a TCP listener on a network interface for remote command-and-control instructions. Which of the following commands should the systems administrator use to generate a list of rogue process names? (Select two).",
    "choices": [
      "netstat -antp | grep LISTEN",
      "lsof -iTCP | grep LISTEN",
      "lsof -i:22 | grep TCP",
      "netstat -a | grep TCP  E. nmap -p1-65535 | grep -i tcp  F. nmap -sS 0.0.0.0/0"
    ],
    "answer": "A"
  },
  {
    "question": "An administrator would like to list all current containers, regardless of their running state. Which of the following commands would allow the administrator to accomplish this task?",
    "choices": [
      "docker ps -a",
      "docker list",
      "docker image ls",
      "docker inspect image"
    ],
    "answer": "A"
  },
  {
    "question": "An administrator has source code and needs to rebuild a kernel module. Which of the following command sequences is most commonly used to rebuild this type of module?",
    "choices": [
      "./configure  make  make install",
      "wget  gcc  cp",
      "tar xvzf  build  cp  tribalsent@yahoo.com 04 Jul 2025",
      "build  install  configure"
    ],
    "answer": "A"
  },
  {
    "question": "A Linux administrator is trying to start the database service on a Linux server but is not able to run it. The administrator executes a few commands and receives the following output:  Which of the following should the administrator run to resolve this issue? (Select two).",
    "choices": [
      "systemctl unmask mariadb",
      "journalctl \u201dg mariadb",
      "dnf reinstall mariadb",
      "systemctl start mariadb  E. chkconfig mariadb on  F. service mariadb reload"
    ],
    "answer": "A"
  },
  {
    "question": "A Linux administrator is troubleshooting an issue in which users are not able to access https://portal.comptia.org from a specific workstation. The administrator runs a few commands and receives the following output:  Which of the following tasks should the administrator perform to resolve this issue?",
    "choices": [
      "Update the name server in resolv. conf to use an external DNS server.",
      "Remove the entry for portal . comptia.org from the local hosts file.",
      "Add a network route from the 10.10.10.0 to the 192.168.0.0.",
      "Clear the local DNS cache on the workstation and rerun the host command."
    ],
    "answer": "B"
  },
  {
    "question": "A Linux administrator needs to transfer a local file named accounts . pdf to a remote / tmp directory  of a server with the IP address 10.10.10.80. Which of the following commands needs to be executed to transfer this file?",
    "choices": [
      "rsync user@10.10.10.80: /tmp accounts.pdf",
      "scp accounts.pdf user@10.10.10.80:/tmp",
      "cp user@10.10.10. 80: /tmp accounts.pdf",
      "ssh accounts.pdf user@10.10.10.80: /tmp"
    ],
    "answer": "B"
  },
  {
    "question": "A systems administrator creates a public key for authentication. Which of the following tools is most suitable to use when uploading the key to the remote servers?",
    "choices": [
      "scp",
      "ssh-copy-id",
      "ssh-agent",
      "ssh-keyscan  tribalsent@yahoo.com 04 Jul 2025"
    ],
    "answer": "B"
  },
  {
    "question": "The application team has reported latency issues that are causing the application to crash on the Linux server. The Linux administrator starts troubleshooting and receives the following output: Which of the following commands will improve the latency issue?",
    "choices": [
      "# echo 'net.core.net_backlog = 5000000' >> /etc/sysctl.conf  tribalsent@yahoo.com 04 Jul 2025 # sysctl -p  # systemctl daemon-reload",
      "# ifdown eth0  # ip link set dev eth0 mtu 800  # ifup eth0",
      "# systemctl stop network  # ethtool -g eth0 512  # systemctl start network",
      "# echo 'net.core.rmem max = 12500000' >> /etc/sysctl.conf  # echo 'net.core.wmem_max = 12500000' >> /etc/sysctl.conf  # sysctl -p"
    ],
    "answer": "D"
  },
  {
    "question": "An administrator runs ping comptia.org. The result of the command is:  ping: comptia.org: Name or service not known Which of the following files should the administrator verify?",
    "choices": [
      "/etc/ethers",
      "/etc/services",
      "/etc/resolv.conf",
      "/etc/sysctl.conf"
    ],
    "answer": "C"
  },
  {
    "question": "Which of the following should be used to verify the integrity of a file?",
    "choices": [
      "sha256sum",
      "fsck",
      "gpg \u201dd",
      "hashcat"
    ],
    "answer": "A"
  },
  {
    "question": "A new application container was built with an incorrect version number. Which of the following commands should be used to rename the image to match the correct version 2.1.2?",
    "choices": [
      "docker tag comptia/app:2.1.1 comptia/app:2.1.2",
      "docker push comptia/app:2.1.1 comptia/app:2.1.2",
      "docker rmi comptia/app:2.1.1 comptia/app:2.1.2",
      "docker update comptia/app:2.1.1 comptia/app:2.1.2"
    ],
    "answer": "A"
  },
  {
    "question": "A Linux administrator wants to prevent the httpd web service from being started both manually and automatically on a server. Which of the following should the administrator use to accomplish this task?",
    "choices": [
      "systemctl mask httpd  tribalsent@yahoo.com 04 Jul 2025",
      "systemctl disable httpd",
      "systemctl stop httpd",
      "systemctl reload httpd"
    ],
    "answer": "A"
  },
  {
    "question": "A non-privileged user is attempting to use commands that require elevated account permissions, but the commands are not successful. Which of the following most likely needs to be updated?",
    "choices": [
      "/etc/passwd",
      "/etc/shadow",
      "/etc/sudoers",
      "/etc/bashrc"
    ],
    "answer": "C"
  },
  {
    "question": "An application developer received a file with the following content: ##This is a sample Image ## FROM ubuntu:18.04 MAINTAINER demohut@gtmail.com.hac COPY . /app RUN make /app CMD python /app/app.py RUN apt-get update RUN apt-get install -y nginx CMD ['echo','Image created'] The developer must use this information to create a test bed environment and identify the image (myimage) as the first version for testing a new application before moving it to production. Which of the following commands will accomplish this task?",
    "choices": [
      "docker build -t myimage:1.0 .",
      "docker build -t myimage: .",
      "docker build -t myimage-1.0 .",
      "docker build -i myimage:1.0 ."
    ],
    "answer": "A"
  },
  {
    "question": "An administrator thinks that a package was installed using a snap. Which of the following commands can the administrator use to verify this information?",
    "choices": [
      "snap list",
      "snap find",
      "snap install",
      "snap try"
    ],
    "answer": "A"
  },
  {
    "question": "A systems administrator created a new directory with specific permissions. Given the following output: # file: comptia # owner: root # group: root user: : rwx group :: r-x other: :---  default:user :: rwx default:group :: r-x default:group:wheel: rwx default:mask :: rwx default:other ::- Which of the following permissions are enforced on /comptia?",
    "choices": [
      "Members of the wheel group can read files in /comptia.",
      "Newly created files in /comptia will have the sticky bit set.",
      "Other users can create files in /comptia.",
      "Only root can create files in /comptia."
    ],
    "answer": "A"
  },
  {
    "question": "A Linux administrator is configuring a new internal web server fleet. The web servers are up and running but can only be reached by users directly via IP address. The administrator is attempting to fix this inconvenience by requesting appropriate records from the DNS team. The details are: Hostname: devel.comptia.org IP address: 5.5.5.1, 5.5.5.2, 5.5.5.3, 5.5.5.4 Name server: 5.5.5.254 Additional names: dev.comptia.org, development.comptia.org Which of the following types of DNS records should the Linux administrator request from the DNS team? (Select three).",
    "choices": [
      "MX",
      "NS",
      "PTR",
      "A  E. CNAME  F. RRSIG  G. SOA  H. TXT  I. SRV"
    ],
    "answer": "B"
  },
  {
    "question": "After connecting to a remote host via SSH, an administrator attempts to run an application but receives the following error: [user@workstation ~]$ ssh admin@srv1 Last login: Tue Mar 29 18:03:34 2022 [admin@srvl ~] $ /usr/local/bin/config_manager Error: cannot open display: [admin@srv1 ~] $ Which of the following should the administrator do to resolve this error?",
    "choices": [
      "Disconnect from the SSH session and reconnect using the ssh -x command.",
      "Add Options X11 to the /home/admin/.ssh/authorized_keys file.",
      "Open port 6000 on the workstation and restart the firewalld service.",
      "Enable X11 forwarding in /etc/ssh/ssh_config and restart the server."
    ],
    "answer": "A"
  },
  {
    "question": "A Linux engineer needs to block an incoming connection from the IP address 2.2.2.2 to a secure shell server and ensure the originating IP address receives a response that a firewall is blocking the connection. Which of the following commands can be used to accomplish this task?",
    "choices": [
      "iptables -A INPUT -p tcp -- dport ssh -s 2.2.2.2 -j DROP",
      "iptables -A INPUT -p tcp -- dport ssh -s 2.2.2.2 -j RETURN",
      "iptables -A INPUT -p tcp -- dport ssh -s 2.2.2.2 -j REJECT",
      "iptables -A INPUT -p tcp -- dport ssh -s 2.2.2.2 -j QUEUE"
    ],
    "answer": "C"
  },
  {
    "question": "A Linux administrator provisioned a new web server with custom administrative permissions for certain users. The administrator receives a report that user1 is unable to restart the Apache web service on this server. The administrator reviews the following output: [ root@server ] # id user1 UID=1011 (user1) gid=1011 (USER1) groups=1011 (user1), 101 (www-data), 1120 (webadmin) [ root@server ] # cat /etc/sudoers.d/custom.conf user1 ALL=/usr/sbin/systemctl start httpd, /usr/sbin/systemctl stop httpd webadmin ALL=NOPASSWD: /etc/init.d.httpd restart, /sbin/service httpd restart, /usr/sbin/apache2ctl restart #%wheel ALL=(ALL) NOPASSWD: ALL Which of the following would most likely resolve the issue while maintaining a least privilege security model?",
    "choices": [
      "User1 should be added to the wheel group to manage the service.",
      "User1 should have 'NOPASSWD:' after the 'ALL=' in the custom. conf.",
      "The wheel line in the custom. conf file should be uncommented.",
      "Webadmin should be listed as a group in the custom. conf file."
    ],
    "answer": "D"
  },
  {
    "question": "An administrator attempts to connect to a remote server by running the following command: $ nmap 192.168.10.36 Starting Nmap 7.60 ( https://nmap.org ) at 2022-03-29 20:20 UTC Nmap scan report for www1 (192.168.10.36) Host is up (0.000091s latency). Not shown: 979 closed ports PORT STATE SERVICE 21/tcp open ftp 22/tcp filtered ssh 631/tcp open ipp Nmap done: 1 IP address (1 host up) scanned in 0.06 seconds Which of the following can be said about the remote server?",
    "choices": [
      "A firewall is blocking access to the SSH server.",
      "The SSH server is not running on the remote server.",
      "The remote SSH server is using SSH protocol version 1.",
      "The SSH host key on the remote server has expired."
    ],
    "answer": "A"
  },
  {
    "question": "A systems administrator notices the process list on a mission-critical server has a large number of processes that are in state 'Z' and marked as 'defunct.' Which of the following should the administrator do in an attempt to safely remove these entries from the process list?",
    "choices": [
      "Kill the process with PID 1.",
      "Kill the PID of the processes.",
      "Kill the parent PID of the processes.",
      "Reboot the server."
    ],
    "answer": "C"
  },
  {
    "question": "A Linux administrator found many containers in an exited state. Which of the following commands will allow the administrator to clean up the containers in an exited state?",
    "choices": [
      "docker rm -- all",
      "docker rm $ (docker ps -aq)",
      "docker images prune *",
      "docker rm -- state exited"
    ],
    "answer": "B"
  },
  {
    "question": "Which of the following is the best tool for dynamic tuning of kernel parameters?",
    "choices": [
      "tuned",
      "tune2fs",
      "tuned-adm",
      "turbostat"
    ],
    "answer": "A"
  },
  {
    "question": "A Linux administrator generated a list of users who have root-level command-line access to the Linux server to meet an audit requirement. The administrator analyzes the following /etc/passwd and /etc/sudoers files: $ cat /etc/passwd  root:x: 0:0: :/home/root: /bin/bash lee: x: 500: 500: :/home/lee:/bin/tcsh mallory:x: 501:501: :/root:/bin/bash eve:x: 502: 502: /home/eve:/bin/nologin carl:x:0:503: :/home/carl:/bin/sh bob:x: 504: 504: : /home/bob:/bin/ksh alice:x: 505:505: :/home/alice:/bin/rsh $ cat /etc/sudoers Cmnd_Alias SHELLS = /bin/tcsh, /bin/sh, /bin/bash Cmnd_Alias SYSADMIN = /usr/sbin/tcpdump ALL = (ALL) ALL ALL = NOPASSWD: SYSADMIN Which of the following users, in addition to the root user, should be listed in the audit report as having root-level command-line access? (Select two).",
    "choices": [
      "Carl",
      "Lee",
      "Mallory",
      "Eve E. Bob F. Alice"
    ],
    "answer": "A"
  },
  {
    "question": "A systems administrator is configuring a Linux system so the network traffic from the internal network 172.17.0.0 going out through the eth0 interface would appear as if it was sent directly from this interface. Which of the following commands will accomplish this task?",
    "choices": [
      "iptables -A POSTROUTING -s 172.17.0.0 -o eth0 -j MASQUERADE",
      "firewalld -A OUTPUT -s 172.17.0.0 -o eth0 -j DIRECT",
      "nmcli masq-traffic eth0 -s 172.17.0.0 -j MASQUERADE",
      "ifconfig -- nat eth0 -s 172.17.0.0 -j DIRECT"
    ],
    "answer": "A"
  },
  {
    "question": "A user is unable to log on to a Linux workstation. The systems administrator executes the following command: cat /etc/shadow | grep user1 The command results in the following output: user1 :! $6$QERgAsdvojadv4asdvaarCdj34GdafGVaregmkdsfa:18875:0:99999:7 ::: Which of the following should the systems administrator execute to fix the issue?",
    "choices": [
      "chown -R userl:user1 /home/user1",
      "sed -i '/ ::: / :: /g' /etc/shadow",
      "chgrp user1:user1 /home/user1",
      "passwd -u user1    tribalsent@yahoo.com 04 Jul 2025"
    ],
    "answer": "D"
  },
  {
    "question": "A Linux engineer finds multiple failed login entries in the security log file for application users. The Linux engineer performs a security audit and discovers a security issue. Given the following: # grep -iE '*www*|db' /etc/passwd www-data:x:502:502:www-data:/var/www:/bin/bash db:x: 505:505:db: /opt/db:/bin/bash Which of the following commands would resolve the security issue?",
    "choices": [
      "usermod -d /srv/www-data www-data && usermod -d /var/lib/db db",
      "passwd -u www-data && passwd -u db",
      "renice -n 1002 -u 502 && renice -n 1005 -u 505",
      "chsh -s /bin/false www-data && chsh -s /bin/false db"
    ],
    "answer": "D"
  },
  {
    "question": "A Linux administrator has defined a systemd script docker-repository.mount to mount a volume for use by the Docker service. The administrator wants to ensure that Docker service does not start until the volume is mounted. Which of the following configurations needs to be added to the Docker service definition to best accomplish this task?",
    "choices": [
      "After=docker-respository.mount",
      "ExecStart=/usr/bin/mount -a  tribalsent@yahoo.com 04 Jul 2025",
      "Requires=docker-repository.mount",
      "RequiresMountsFor=docker-repository.mount"
    ],
    "answer": "C"
  },
  {
    "question": "Which of the following will prevent non-root SSH access to a Linux server?",
    "choices": [
      "Creating the /etc/nologin file",
      "Creating the /etc/nologin.allow file containing only a single line root",
      "Creating the /etc/nologin/login.deny file containing a single line +all",
      "Ensuring that /etc/pam.d/sshd includes account sufficient pam_nologin.so"
    ],
    "answer": "A"
  },
  {
    "question": "A systems administrator is gathering information about a file type and the contents of a file. Which of the following commands should the administrator use to accomplish this task?",
    "choices": [
      "file filename",
      "touch filename",
      "grep filename  tribalsent@yahoo.com 04 Jul 2025",
      "lsof filename"
    ],
    "answer": "A"
  },
  {
    "question": "Users are reporting that writes on a system configured with SSD drives have been taking longer than expected, but reads do not seem to be affected. A Linux systems administrator is investigating this issue and working on a solution. Which of the following should the administrator do to help solve the issue?",
    "choices": [
      "Run the corresponding command to trim the SSD drives.",
      "Use fsck on the filesystem hosted on the SSD drives.",
      "Migrate to high-density SSD drives for increased performance.",
      "Reduce the amount of files on the SSD drives.  tribalsent@yahoo.com 04 Jul 2025"
    ],
    "answer": "A"
  },
  {
    "question": "The development team created a new branch with code changes that a Linux administrator needs to pull from the remote repository. When the administrator looks for the branch in Git, the branch in question is not visible. Which of the following commands should the Linux administrator run to refresh the branch information?",
    "choices": [
      "git fetch",
      "git checkout",
      "git clone",
      "git branch"
    ],
    "answer": "A"
  },
  {
    "question": "A file called testfile has both uppercase and lowercase letters: $ cat testfile  ABCDEfgH IJKLmnoPQ abcdefgH ijklLMNopq A Linux administrator is tasked with converting testfile into all uppercase and writing it to a new file with the name uppercase. Which of the following commands will achieve this task?",
    "choices": [
      "tr '(A-Z}' '{a-z}' < testfile > uppercase",
      "echo testfile | tr '[Z-A]' '[z-a]' < testfile > uppercase",
      "cat testfile | tr '{z-a)' '{Z-A}' < testfile > uppercase",
      "tr '[a-z]' '[A-Z]' < testfile > uppercase"
    ],
    "answer": "D"
  },
  {
    "question": "A Linux administrator is troubleshooting a systemd mount unit file that is not working correctly. The file contains: [root@system] # cat mydocs.mount [Unit] Description=Mount point for My Documents drive [Mount] What=/dev/drv/disk/by-uuidafc9b2-ac34-ccff-88ae-297ab3c7ff34 Where=/home/user1/My Documents Options=defaults Type=xfs [Install] WantedBy=multi-user.target The administrator verifies the drive UUID correct, and user1 confirms the drive should be mounted  as My Documents in the home directory. Which of the following can the administrator do to fix the issues with mounting the drive? (Select two).",
    "choices": [
      "Rename the mount file to home-user1-My\\\\x20Documents.mount.",
      "Rename the mount file to home-user1-my-documents.mount.",
      "Change the What entry to /dev/drv/disk/by-uuidafc9b2\\\\-ac34\\\\-ccff\\\\-88ae\\\\-297ab3c7ff34.",
      "Change the Where entry to Where=/home/user1/my\\\\ documents.  E. Change the Where entry to Where=/home/user1/My\\\\x20Documents.  F. Add quotes to the What and Where entries, such as What='/dev/drv/disk/by-uuidafc9b2-ac34-  ccff-88ae-297ab3c7ff34' and Where='/home/user1/My Documents'."
    ],
    "answer": "A"
  },
  {
    "question": "Following the migration from a disaster recovery site, a systems administrator wants a server to require a user to change credentials at initial login. Which of the following commands should be used to ensure the aging attribute?",
    "choices": [
      "chage -d 2 user",
      "chage -d 0 user",
      "chage -E 0 user",
      "chage -d 1 user"
    ],
    "answer": "B"
  },
  {
    "question": "A systems administrator needs to remove a disk from a Linux server. The disk size is 500G, and it is the only one that size on that machine. Which of the following commands can the administrator use to find the corresponding device name?",
    "choices": [
      "fdisk -V",
      "partprobe -a",
      "lsusb -t",
      "lsscsi -s"
    ],
    "answer": "D"
  },
  {
    "question": "A Linux user is trying to execute commands with sudo but is receiving the following error: $ sudo visudo >>> /etc/sudoers: syntax error near line 28 <<< sudo: parse error in /etc/sudoers near line 28 sudo: no valid sudoers sources found, quitting The following output is provided: # grep root /etc/shadow root :* LOCK *: 14600 :::::: Which of the following actions will resolve this issue?",
    "choices": [
      "Log in directly using the root account and comment out line 28 from /etc/sudoers.",
      "Boot the system in single user mode and comment out line 28 from /etc/sudoers. tribalsent@yahoo.com 04 Jul 2025",
      "Comment out line 28 from /etc/sudoers and try to use sudo again.",
      "Log in to the system using the other regular user, switch to root, and comment out line 28 from  /etc/sudoers."
    ],
    "answer": "B"
  },
  {
    "question": "A Linux system is having issues. Given the following outputs: # dig @192.168.2.2 mycomptiahost ; << >> DiG 9.9.4-RedHat-9.9.4-74.el7_6.1 << >> @192.168.2.2 mycomptiahost ; (1 server found) ;; global options: +cmd ;; connection timed out; no servers could be reached # nc -v 192.168.2.2 53 Ncat: Version 7.70 ( https://nmap.org/ncat ) Ncat: Connection timed out. # ping 192.168.2.2 PING 192.168.2.2 (192.168.2.2) 56(84) bytes of data. 64 bytes from 192.168.2.2: icmp_seq=1 ttl=117 time=4.94 ms 64 bytes from 192.168.2.2: icmp_seq=2 ttl=117 time=10.5 ms Which of the following best describes this issue?",
    "choices": [
      "The DNS host is down.",
      "The name mycomptiahost does not exist in the DNS.",
      "The Linux engineer is using the wrong DNS port.",
      "The DNS service is currently not available or the corresponding port is blocked."
    ],
    "answer": "D"
  },
  {
    "question": "Users are experiencing high latency when accessing a web application served by a Linux machine. A systems administrator checks the network interface counters and sees the following: Which of the following is the most probable cause of the observed latency?",
    "choices": [
      "The network interface is disconnected.",
      "A connection problem exists on the network interface.",
      "No IP address is assigned to the interface.",
      "The gateway is unreachable."
    ],
    "answer": "B"
  },
  {
    "question": "While troubleshooting server issues, a Linux systems administrator obtains the following output: [rootGhost ~]# total free -m used free shared buf f/cache available Mem: 3736 3598 88 2 48 29 Swap: 2047 1824 223 Which of the following best describes the state of the system?",
    "choices": [
      "The system has consumed the system memory and swap space.",
      "The system has enough free memory space.",
      "The system has swap disabled.",
      "The system has allocated enough buffer space."
    ],
    "answer": "B"
  },
  {
    "question": "A network administrator issues the dig ww. compti a. org command and receives an NXDOMAIN response. Which of the following files should the administrator check first?",
    "choices": [
      "/etc/resolv.conf",
      "/etc/hosts",
      "/etc/sysconfig/network-scripts",
      "/etc/nsswitch.conf"
    ],
    "answer": "A"
  },
  {
    "question": "An administrator is running a web server in a container named web, but none of the error output is not showing. Which of the following should the administrator use to generate the errors on the container?",
    "choices": [
      "docker-compose inspect WEB",
      "docker logs WEB",
      "docker run \u201dname WEB \u201dvolume/dev/stdout:/var/log/nginx/error.log",
      "docker ps WEB -f"
    ],
    "answer": "B"
  },
  {
    "question": "A technician just fixed a few issues in some code and is ready to deploy the code into production. Which of the following steps should the technician take next?",
    "choices": [
      "Create a new branch using git checkout.",
      "Perform a git clone to pull main down.",
      "Create a git pull request to merge into main.",
      "Perform a git pull to update the local copy of the code."
    ],
    "answer": "C"
  },
  {
    "question": "Due to performance issues on a server, a Linux administrator needs to terminate an unresponsive process. Which of the following commands should the administrator use to terminate the process immediately without waiting for a graceful shutdown?",
    "choices": [
      "kill -SIGKILL 5545",
      "kill -SIGTERM 5545",
      "kill -SIGHUP 5545",
      "kill -SIGINT 5545"
    ],
    "answer": "A"
  },
  {
    "question": "A Linux administrator is troubleshooting an SSHD issue on a server. Users are receiving error messages stating the connection is refused. Which of the following commands should be used to verify whether the service is listening?",
    "choices": [
      "nslookup",
      "route",
      "netstat",
      "ifconfig"
    ],
    "answer": "C"
  },
  {
    "question": "A Linux administrator is tasked with moving files in a database server. The administrator must not overwrite any existing files. Which of the following commands would indicate that the file already exists?",
    "choices": [
      "mv -i filename /tmp/backup",
      "mv -b filename /tmp/backup",
      "mv -n filename /tmp/backup",
      "mv -f filename /tmp/backup"
    ],
    "answer": "A"
  },
  {
    "question": "A Linux administrator needs to determine if prerequisites are met. One of the application requirements is to install Perl on a system. Which of the following commands would accomplish this task?",
    "choices": [
      "rpm -Uf perl",
      "rpm -iv perl",
      "rpm -qa perl",
      "rpm -eh perl"
    ],
    "answer": "C"
  },
  {
    "question": "The journald entries have filled a Linux machine's /var volume. Which of the following is the best  command for a systems administrator to use to free up the disk space occupied by these entries?",
    "choices": [
      "journalctl \u201drotate  journalctl --vacuum-time=ls",
      "systemctl stop systemd-journald  systemctl start systemd-journald",
      "rm -rf /var/log/journal  systemctl restart systemd-journald",
      "pkill -HUP systemd-journald  systemctl restart systemd-journald"
    ],
    "answer": "B"
  },
  {
    "question": "An administrator is provisioning an Apache web server. When the administrator visits the server website, the browser displays a message indicating the website cannot be reached. Which of the following commands should the administrator use to verify whether the service Is running?",
    "choices": [
      "systemctl status httpd",
      "systemctl mask httpd",
      "systemctl reload httpd",
      "systemctl restart httpd"
    ],
    "answer": "A"
  },
  {
    "question": "A user (userA) has reported issues while logging in to the system. The following output has been provided: bash Could not chdir to home directory /home/userA: Permission denied -bash: /home/userA/.bash_profile: Permission denied # cat /etc/passwd | grep userA userA:x:1234:3400:userA account:/home/userA/:/bin/bash # passwd -S userA userA PS 2022-10-17 1 99999 0 (Password set. SHA512 crypt.) # groups userA admin dev usergrp # ls -lth /home/ drwx------ 7 root admin 9 Jan 17 2019 userA drwxr-xr-x 4 userC app 9 Jan 23 2020 userC Which of the following describes the issue userA is having?",
    "choices": [
      "The password for userA is not set",
      "The group for userA is not assigned correctly",
      "The account password for userA has expired",
      "The assigned home directory is not owned by userA"
    ],
    "answer": "D"
  },
  {
    "question": "Which of the following commands is used to tune kernel parameters?",
    "choices": [
      "sysctl",
      "ss",
      "mkinitrd",
      "lsof  tribalsent@yahoo.com 04 Jul 2025"
    ],
    "answer": "A"
  },
  {
    "question": "A security team discovers that a web server has been running with elevated privileges and identifies it as a security violation. Which of the following items needs to be added to the webserver.service file to remediate the issue?",
    "choices": [
      "In the [Service] section of the webserver.service file, add User=comptia.",
      "In the [Unit] section of the webserver.service file, add AllowIsolate=true.",
      "In the [Install] section of the webserver.service file, add WantedBy=single.target.",
      "Add After=network.target to the [Install] section of the webserver.service file."
    ],
    "answer": "A"
  },
  {
    "question": "Which of the following paths stores the configuration files in a Linux filesystem?",
    "choices": [
      "/proc",
      "/home",
      "/root",
      "/etc"
    ],
    "answer": "D"
  },
  {
    "question": "The users of a Linux system are unable to use one of the application filesystems. The following outputs have been provided: bash $ cd /app $ touch file touch: cannot touch 'file': Readonly file system Output 2 /dev/sdcl on /app type ext4 (ro,relatime,seclabel,data=ordered) Output 3 /dev/sdcl /app ext4 defaults 0 0 Output 4 [302.048075] Buffer I/O error on dev sdcl, logical block 0, async page read [302.048490] EXT4-fs (sdcl): Attempt to read block from filesystem resulted in short read while trying to re-open /dev/sdcl Which of the following actions will resolve this issue?",
    "choices": [
      "umount /app fsck -y /dev/sdcl mount /app",
      "xfs_repair /dev/sdcl mount -o rw,remount /app",
      "umount /app xfs_repair /dev/sdcl mount /app",
      "fsck -y /dev/sdcl mount -o rw,remount /app"
    ],
    "answer": "D"
  },
  {
    "question": "A systems administrator is tasked with configuring a repository on an RPM-based Linux system. Which of the following need to be reviewed and modified? (Select two).",
    "choices": [
      "/etc/yum.conf tribalsent@yahoo.com 04 Jul 2025",
      "/etc/apt/sources.list.d",
      "/etc/pam.d",
      "/etc/apt.conf E. /etc/yum.repos.d F. /etc/ssh/ssh_config"
    ],
    "answer": "A"
  },
  {
    "question": "A systems administrator receives the following errors via email from the system log: go XFS (loop0): Metadata CRC error detected at xfs_agi_read_verify+0xcb/0xfe XFS (loop0): First 128 bytes of corrupted metadata buffer XFS (loop0): metadata I/O error in 'xfs_trans_read_buf_map' at daddr 0x2 len 1 error 74 A few minutes later, the administrator starts receiving reports that some of the images in the company's website are not loading properly. The systems administrator runs some commands and receives the following outputs: css Output 1 NAME FSTYPE UUID MOUNTPOINT sda ext4 02ae47-fe457-45bc / sdb xfs 347c7056 /var/www/html Output 2 DocumentRoot '/var/www/html' Output 3 httpd.service - The Apache HTTP Server Loaded: loaded (/usr/lib/systemd/system/httpd.service; enabled; vendor preset: disabled) Active: active (running) since Sun 1991-05-24 16:12:43 UTC; 30y ago Main PID: 252 (httpd) Which of the following would be the appropriate steps to take to solve this issue?",
    "choices": [
      "systemctl stop httpd umount /dev/sdb1 xfs_repair /dev/sdb1 mount /dev/sdb1 /var/www/html tribalsent@yahoo.com 04 Jul 2025 systemctl start httpd",
      "umount /dev/sdb1 xfs_repair /dev/sdb1 xfs_metadump /dev/sdb1 mount /dev/sdb1 /var/www/html systemctl restart httpd",
      "umount /dev/sdb1 systemctl stop httpd xfs_metadump /dev/sdb1 mount /dev/sdb1 /var/www/html systemctl start httpd",
      "systemctl stop httpd xfs_check -L /dev/sdb umount /var/www/html systemctl start httpd"
    ],
    "answer": "A"
  },
  {
    "question": "A Linux administrator created a virtual clone of a physical server and would like to remove any existing entries related to SSH keys from outside entities on the virtual clone. Which of the following files should the administrator remove? (Select two).",
    "choices": [
      "~/.ssh/authorized_keys",
      "~/.ssh/known_hosts",
      "/etc/ssh/ssh_config",
      "~/.ssh/config E. /etc/ssh/sshd_config F. /etc/ssh/ssh_host_rsa_key.pub"
    ],
    "answer": "A"
  },
  {
    "question": "A systems administrator wants to list all local account names and their respective UIDs. Which of the following commands will provide output containing this information?",
    "choices": [
      "cut -c: -f3,1 /etc/passwd",
      "cut -d: -s2,3 /etc/passwd",
      "cut -d: -f1,3 /etc/passwd",
      "cut -n: -f1,2 /etc/passwd"
    ],
    "answer": "C"
  },
  {
    "question": "A Linux systems administrator is trying to execute a particular shell script on a server. The administrator reviews the following outputs: shell $ ./startup.sh bash: ./startup.sh: Permission denied $ ls -l startup.sh -rw-rw-r-- 1 companyabc companyabc 18 October 15:35 startup.sh Which of the following commands should the administrator use to allow the script to run?",
    "choices": [
      "chown root  startup.sh",
      "chmod 750 startup.sh",
      "chmod -x startup.sh",
      "chmod 400 startup.sh"
    ],
    "answer": "B"
  },
  {
    "question": "A user is cleaning up a directory because it has more than 100,000 files that were generated from an experiment. When the user tries to remove the unneeded experiment files, the user receives an error: arduino cannot execute [Argument list too long] Which of the following should the user execute to remove these files?",
    "choices": [
      "find . -name 'experiment*.txt' -exec rm '{}' ;",
      "rm -rf experiment*.txt",
      "rm --force experiment*.txt",
      "for i in experiment*.txt; do find . -name $i -exec rmdir '{}' ; done"
    ],
    "answer": "A"
  },
  {
    "question": "A Linux administrator is implementing a CI/CD process for the companys internal accounting web application. Which of the following best defines the purpose of this process?",
    "choices": [
      "To automate the process of building, testing, and deploying application components",
      "To perform security penetration tests on deployed applications to identify vulnerabilities",
      "To formalize the approval process of application releases and configuration changes",
      "To leverage code to document the infrastructure, configurations, and dependencies"
    ],
    "answer": "A"
  },
  {
    "question": "A systems administrator is customizing a new Linux server. Which of the following settings for umask would ensure that new files have the default permissions of -rw-r--r--?",
    "choices": [
      "0017",
      "0027",
      "0038",
      "0640"
    ],
    "answer": "B"
  },
  {
    "question": "An administrator accidentally installed the httpd RPM package along with several dependencies. Which of the following options is the best way for the administrator to revert the package installation?",
    "choices": [
      "dnf clean all",
      "rpm -e httpd",
      "apt-get clean",
      "yum history undo last"
    ],
    "answer": "D"
  },
  {
    "question": "A Linux administrator is configuring a log collector agent to monitor logs in /var/log/collector. The agent is reporting that it cannot write to the directory. The agent runs as the logger user account. The administrator runs a few commands and reviews the following output:  makefile Output 1: drwxr-xr-x. 1 root root 0 Oct 20:13 collector Output 2: file: /var/log/collector owner: root group: root user::rwx group::r-x mask::rwx other::r-x Output 3: uid=1010(logger) gid=1010(monitor) groups=1010(monitor) Which of the following is the best way to resolve the issue?",
    "choices": [
      "setfacl -Rm u:logger  /var/log/collector",
      "usermod -aG root logger",
      "chmod 644 /var/log/collector",
      "chown -R logger  /var/log"
    ],
    "answer": "A"
  },
  {
    "question": "An administrator is running a web server in a container named WEB, but none of the error output is showing. Which of the following should the administrator use to generate the errors on the container?",
    "choices": [
      "docker-compose inspect WEB",
      "docker logs WEB",
      "docker run --name WEB --volume /dev/stdout:/var/log/nginx/error.log  tribalsent@yahoo.com 04 Jul 2025",
      "docker ps WEB -f"
    ],
    "answer": "B"
  },
  {
    "question": "A Linux systems administrator is working to obtain the installed kernel version of several hundred systems. Which of the following utilities should the administrator use for this task?",
    "choices": [
      "Ansible",
      "Git",
      "Docker",
      "Bash"
    ],
    "answer": "A"
  },
  {
    "question": "A systems administrator identifies multiple processes in a zombie state. Which of the following signals would be best for the administrator to send to the PPID?",
    "choices": [
      "SIGTERM",
      "SIGHUP",
      "SIGQUIT",
      "SIGSTOP"
    ],
    "answer": "A"
  },
  {
    "question": "A Linux administrator needs to check extended permissions applied to the directory test. Which of the following commands should the administrator use to help with this task?",
    "choices": [
      "getsebool test/",
      "getenforce test/",
      "getfacl test/",
      "ls -al test/"
    ],
    "answer": "C"
  },
  {
    "question": "A DevOps engineer is working on a local copy of a Git repository. The engineer would like to switch from the main branch to the staging branch but notices the staging branch does not exist. Which of the following Git commands should the engineer use to perform this task?",
    "choices": [
      "git branch -m staging",
      "git commit -m staging",
      "git status -b staging",
      "git checkout -b staging"
    ],
    "answer": "D"
  },
  {
    "question": "An operations engineer is planning to start a container running a PostgreSQL database. The engineer wants the container to start automatically at system startup, mount the /home/db directory as /var/lib/postgresql inside the container, and expose port 5432 to the OS. Which of the following commands should the engineer run to achieve this task?",
    "choices": [
      "docker run -d --restart always -p 5432:5432 -v /home/db:/var/lib/postgresql postgresql:12",
      "docker run -d --restart -p 5432:5432 --volume /var/lib/postgresql:/home/db postgresql:12",
      "docker run -d --attach --platform 5432:5432 --volume /home/db:/var/lib/postgresql postgresql:12",
      "docker run -d --init --restart --publish 5432:5432 --workdir /home/db:/var/lib/postgresql  postgresql:12"
    ],
    "answer": "A"
  },
  {
    "question": "A Linux administrator would like to measure possible packet loss between a workstation and a remote web application that is running on port 443. Which of the following would be the best command for the administrator to use to display this information?",
    "choices": [
      "ping -c 50 <remote server IP>",
      "tcpdump -p 443 <remote server IP>",
      "mtr -T -P 443 <remote server IP>",
      "traceroute -p 443 <remote server IP>"
    ],
    "answer": "C"
  },
  {
    "question": "Users have been unable to reach www.comptia.org from a Linux server. A systems administrator is troubleshooting the issue and runs the following commands:\n\n```bash\n$ ping www.comptia.org\nping: unknown host www.comptia.org\n\n$ dig www.comptia.org\n;; connection timed out; no servers could be reached\n\n$ cat /etc/resolv.conf\nnameserver 127.0.0.53\n```",
    "choices": [
      "The firewall is blocking outbound web traffic",
      "The local DNS resolver is not functioning properly",
      "The www.comptia.org domain does not exist",
      "The network cable is disconnected"
    ],
    "answer": "B"
  }
];