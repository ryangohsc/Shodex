# Background 
The growth of the Internet of Things (IoT) devices has continued to grow gradually throughout the years. By 2025, there will be about an estimated 75 billion IoT devices globally. Given the design nature and computing constraints of IoT devices, they are vulnerable to cyber security threats. Although IoT security is starting to gain attention, there is still a lack of comprehensive commercial tools to perform the scanning and penetration testing of IoT devices, leading to many developing their own frameworks and tools.

# Project Shodex  
Shodex is a tool is developed for Linux. It aims to streamline the IoT penetration testing methodology into a minimal user interaction command-line tool. It leverages the Shodan API to search for vulnerable IoT devices based on the user's filters.  

![image](https://user-images.githubusercontent.com/32363441/159154712-12502479-1e7f-4e9b-98b9-d36bd6897480.png)

# Features 
**1) Scan for Vulnerabilities**

Shodex would scan the device for its running services and search for vulnerabilities based on them. 

**2) Recommend Exploits** 

Vulnerabilities found by Shodex would be primarily searched against exploit-db for any existing exploits. Should the vulnerability exist but there are no available exploits to recommend from exploit-db, Shodex would search against Packet Storm and GitHub instead. 

**3) Auto-configure Exploits**

Exploits recommended, or any local exploits provided by the user to Shodex can be auto-configured and executed if it is possible.

# Mode of Operations 
**Step 1:** Use the Shodan API to search for vulnerable IoT devices based on the user’s search filters if the user specifies the online mode. 

**Step 2:** Run a Nmap scan on the target and brute force modules if network auth services such as SSH, Telnet, FTP, and HTTP auth exists.

**Step 3:** Crawls its local exploit database for publicly available exploits for the selected target and suggests usable exploits.

**Step 4:** The user will have the option to use the suggested publicly available exploits or use the inbuilt exploits if it exists.

**Step 5:** Afterwards, upon selecting an exploit, Shodex will autoconfigure and execute the payload onto the target device if deemed possible.
  
# First Run Setup  
**Dependencies:**  
- git
- nmap
- ssh
- python3
  
**Installing Python Dependency & Updating:**
```
pip3 install requirements.txt
python3 main.py --update
```

# Usage  
### Updating the Tool (Requires Internet Connection)
```
python3 main.py --update
```
### Online Scanning
```
python3 main.py --filter ip:[IP Address],city:[CITY],country:[COUNTRY] --api_key [Shodan API Key]
```
For a list of all the filters, visit Shodan's webpage.
### Online Scanning with Bruteforce Mode
```
python3 main.py --filter ip:[IP Address],city:[CITY],country:[COUNTRY] --api_key [Shodan API Key] --brute
```
### Offline Scanning
```
python3 main.py --target [IP Address] --speed [Optional: Fast]
```
### Offline Scanning with Bruteforce Mode
```
python3 main.py --target [IP Address] --speed [Optional: Fast] --brute
```

# Team Members
###### Lab Group P1 - Team Pizzaluvers
- **Team Leader**: Ryan Goh (1802980)
- **Team Member**: Alicia Fang Yan Jie (2002559)
- **Team Member**: Koh Jun Jie (2000819)  
