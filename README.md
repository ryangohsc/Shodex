# Shodex  
Shodex is a tool is developed for Linux. It aims to streamline the IoT penetration testing methodology. It leverages the Shodan API to search for vulnerable IoT devices based on the user's filters.  

# Team Members
###### Lab Group P1 - Team Pizzaluvers
- **Team Leader**: Ryan Goh (1802980)
- **Team Member**: Alicia Fang Yan Jie (2002559)
- **Team Member**: Koh Jun Jie (2000819)  

## Usage  
### Updating the Tool (Requires Internet Connection)
```
python3 main.py --update
```
### Online Scanning
```
python3 main.py --filter ip:[IP Address] --api_key [Shodan API Key]
```
### Online Scanning with Bruteforce Mode
```
python3 main.py --filter ip:[IP Address] --api_key [Shodan API Key] --brute
```
### Local Scanning
```
python3 main.py --target [IP Address] --speed [Optional: Fast]
```
### Local Scanning with Bruteforce Mode
```
python3 main.py --target [IP Address] --speed [Optional: Fast] --brute
```
