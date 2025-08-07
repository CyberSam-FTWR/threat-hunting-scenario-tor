<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/CyberSam-FTWR/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

### 1. Searched the `DeviceFileEvents` Table

I searched the DeviceFileEvent table for ANY file that had the string “tor” in it and discovered what looks like the user “cyberbunny” downloaded a tor installer, did some action that related in many tor-related files being copied to the desktop and the creation of a file called “tor-shopping-list” on the desktop at “2025-08-06T12:22:09.0087639Z”. These events began at “2025-08-06T12:06:05.389868Z”

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "sam-ftwr"
| where InitiatingProcessAccountName == "cyberbunny"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-08-06T12:06:05.389868Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="">

---

### 2. Searched the `DeviceProcessEvents` Table

I searched the DeviceProcessEvents table for ANY ProcessCommandLine that contained the string “tor-browser-windows-x86_64-portable-14.5.5.exe /S”. Based on the logs return, at 2025-08-06T12:06:05.389868Z, a user named "CyberBunny" on a device called "sam-ftwr" silently launched the installation of the Tor Browser from their Downloads folder, running the file "tor-browser-windows-x86_64-portable-14.5.5.exe /S" using a command to install it without showing any prompts. 

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "sam-ftwr"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.5.exe  /S"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

I searched the DeviceProcessEvents table for ANY indication that the user account “CyberBunny” actually opened the tor-browser. There was evidence that they did opened it at “2025-08-06T12:08:21.8645074Z”. There were several other instances of firefox.exe as well as tor.exe spawned after.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "sam-ftwr"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe", "torbrowser.exe", "start-tor-browser.exe", "torbrowser-install-win64.exe", "torbrowser-install-win32.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1212" alt="image" src="">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

I searched the DeviceNetworkEvents table for ANY indication the tor-browser was used to establish a connection using any of the known tor ports. At, 2025-08-06T12:08:33.8407489Z, the user "CyberBunny" on the device "sam-ftwr" successfully established another Tor connection to the IP address 213.165.93.177 over port 9001. The connection was initiated by the Tor executable ("tor.exe") located in the Tor Browser folder on their desktop. There were a couple other connections to sites over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "sam-ftwr"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9050", "9051", "9150", "9151", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1212" alt="image" src="">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-06-08 T12:06:05.389868Z`
- **Event:** The user "CyberBunny" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\CyberBunny\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - Silent Installation of Tor Browser

- **Timestamp:** `2025-06-08 T12:06:05.389868Z`
- **Event:** The user "CyberBunny" executed the Tor Browser installer tor-browser-windows-x86_64-portable-14.5.5.exe using a silent install flag (/S) from their Downloads folder.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\CyberBunny\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`
- **Significance:** Indicates intentional installation of Tor Browser with no user prompts.

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-08-08T12:08:21.8645074Z`
- **Event:** User "CyberBunny" executed the Tor Browser for the first time. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\CyberBunny\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`
- **Significance:** Confirms user interaction with and execution of the Tor Browser.

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-06-08T12:08:33.8407489Z`
- **Event:** A network connection to IP `213.165.93.177` on port `9001` by user "CyberBunny" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\CyberBunny\desktop\tor browser\browser\torbrowser\tor\tor.exe`
- **Significance:** Confirms Tor network communication and likely anonymized browsing behavior.

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:0(FILL IN INFORMATION)` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z(FILL IN INFORMATION)` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "CyberBunny" through the TOR browser.
- **Action:** Multiple successful connections detected.
- **Significance:** Confirms Tor network communication and likely anonymized browsing behavior.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-06-08T12:22:09.0087639Z`
- **Event:** The user "CyberBunny" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\CyberBunny\Desktop\tor-shopping-list.txt`
- **Significance:** Indicates user-generated content possibly related to Tor usage or intent.

---

## Summary

The user "CyberBunny" on the "sam-ftwr" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `sam-ftwr` by the user `CyberBunny`. The device was isolated, and the user's direct manager was notified.

---
