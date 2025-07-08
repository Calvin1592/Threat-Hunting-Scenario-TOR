# Threat-Hunting-Scenario-TOR

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

Searched the DeviceFileEvents table for any file that had the string “tor” in it and discovered what look like the user “bigc1592” downloaded a “tor” installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor-shopping-list.txt” on the desktop at 2025-06-30T20:09:00.674288Z. These events began at: 2025-06-30T19:53:05.2138333Z.

Query used to locate events:

DeviceFileEvents
| where DeviceName == "threathuntingca"
| where InitiatingProcessAccountName == "bigc1592"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-06-30T19:53:05.2138333Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string “tor-browser-windows-x86_64-portable-14.5.4.exe.” Based on the logs returned, at 
Jun 30, 2025 7:59:43 PM, an employee on the “bigc1592” device “threathuntingca” silently launched the Tor Browser installer from their Downloads folder using a command that avoided any prompts or user interface. 

Query used to locate event:

DeviceProcessEvents
| where DeviceName == "threathuntingca"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.4.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

Searched the DeviceProcessEvents table for any indication that the user “bigc1592” actually opened the tor browser. There was evidence that they did open it at: Jun 30, 2025 8:00:10 PM
There were several other instances of Firefox.exe (Tor) as well as tor.exe spawned afterwards.

Query used to locate event:

DeviceProcessEvents
| where DeviceName == "threathuntingca"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports. At 2025-06-30T20:00:49.5154683Z, an employee on the “threathuntingca” device successfully made a network connection using the program tor.exe, located in the Tor Browser folder on their desktop. The connection was made to the remote IP address 185.225.18.102 on port 9001. There were a few other connections to sites over port 443.

Query used to locate events:

DeviceNetworkEvents
| where DeviceName == "threathuntingca"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc









Chronological Events
Timeline of Events:

1. 2025-06-30T19:53:05.2138333Z - Event: User "bigc1592" begins activities related to Tor. - Action: The user initiated the process of downloading files that contain "tor".

2. 2025-06-30T20:09:00.674288Z - Event: A file named “tor-shopping-list.txt” is created on the desktop. - Action: Several tor-related files are copied to the desktop.

3. 2025-06-30T19:59:43Z - Event: "bigc1592" silently launches the Tor Browser installer. - Details: The command executed avoided prompts or a user interface.

4. 2025-06-30T20:00:10Z - Event: The Tor Browser is opened by the user "bigc1592". - Action: Following this, multiple instances of "firefox.exe" (associated with Tor) and "tor.exe" are spawned.

5. 2025-06-30T20:00:49.5154683Z - Event: A successful network connection is established using "tor.exe". - Details: The connection is made to remote IP address 185.225.18.102 on port 9001.

6. Post 20:00:49.5154683Z - Event: Additional connections are made to various sites over port 443.






Summary
On June 30, 2025, at approximately 7:53 PM, user "bigc1592" began downloading files related to the Tor browser, which resulted in the creation of a document named “tor-shopping-list.txt”. Shortly thereafter, the user silently launched the installer for the Tor Browser from their device, circumventing any prompts that would normally appear. At 8:00 PM, they successfully opened the Tor Browser and initiated the program "tor.exe". This led to the establishment of a network connection on port 9001 to a specified remote IP address, along with subsequent connections over port 443. The actions taken by the user suggest a deliberate attempt to use the Tor browser, and the method of installation and execution indicates an intention to hide activity, which warrants further investigation. Users involved in this case may require additional monitoring and awareness training around the risks associated with using Tor.


Response Taken
TOR usage was confirmed on endpoint threathuntingca. The device was isolated and the user's direct manager was notified.










