# ProxyNotShell Scanner

1. Change the API key in shodan-query.py
2. Run shodan-query.py to grab results (You can change the query in the file)
3. Run check.py to check if Outlook servers are vulnerable to ProxyNotShell

## Mass Scanner
Trhacknon mass scanner(https://github.com/trhacknon/CVE-2022-41082-MASS-SCANNER)

## Exploit
[!] Usage: python3 CVE-2022-41040.py -u https://mail.example.com -c example.burpcollaborator.net 

Modded by Trhacknon

# List of Dorks

` http.favicon.hash:1768726119 (Shodan) `

` http.component:"outlook web app" (Shodan) `

` http.component:"outlook web app" ssl:"hybrid" (Shodan) `

` tag.name:"microsoft_exchange" prot7:http http.status_code:200 (Netlas.io) `

` same_service(http://services.http.response.favicons.name: */owa/auth/* and services.http.response.html_title={"Outlook Web App", "Outlook"}) (Censys) `
