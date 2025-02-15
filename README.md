<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/john-rogers13/Threat-Hunting-Scenario-Tor-Browser-Usage-/commit/34013655527c86183ea44a481feb64c51593dfe0)

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

Searched table for any file that had the string “tor’ in it and discovered what looks like the user “jtex” downloaded a tor installer. Many files were being copied to the desktop with the creation of a file named “tor-shopping-list.txt” on to the desktop. These events began at: 2025-02-13T01:56:06.1210159Z

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName startswith "tor"
| where DeviceName == "ehreat-hunt-lab"
|order by Timestamp desc
|project Timestamp, DeviceName, ActionType, FileName, SHA256, Account = InitiatingProcessAccountName

```
![image](https://github.com/user-attachments/assets/f1327f9b-11cb-4364-b333-9e75d8e403f0)


---

### 2. Searched the `DeviceProcessEvents` Table

Searched DeviceFileEvents and found that On the evening of February 12, 2025, at 7:01 PM, user 'jtex' on the device named 'ehreat-hunt-lab' initiated the installation of 'tor-browser-windows-x86_64-portable-14.0.6.exe' from the 'Downloads' folder using the '/S' command-line option, which typically signifies a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-windows"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, AccountName, ProcessCommandLine
| where DeviceName == "ehreat-hunt-lab"

```
![image](https://github.com/user-attachments/assets/890d0ac8-2249-4bc4-803e-a1e7d548fb33)


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched DeviceNetworkEvents table for any indication tor browser was used. At 7:02 PM on February 12, 2025, the Firefox browser on the device 'ehreat-hunt-lab' successfully connected to a local service on IP address 127.0.0.1 using port 9150. This suggests that Firefox was likely configured to route its traffic through the Tor network, as port 9150 is commonly used by the Tor service for secure browsing.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "ehreat-hunt-lab"
| where InitiatingProcessAccountName  != "system"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| project  Timestamp, DeviceName, RemoteIP, RemotePort, ActionType, InitiatingProcessCommandLine

```
![image](https://github.com/user-attachments/assets/48767b64-f8e8-47fd-8cd8-42bb139812fd)


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** February 12, 2025, 7:01 PM
- **Event:** User 'jtex' on the device 'ehreat-hunt-lab' initiated the installation of 'tor-browser-windows-x86_64-portable-14.0.6.exe' from the 'Downloads' folder using the '/S' command-line option, indicating a silent installation.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. File Creation - TOR Shopping List

- **Timestamp:** February 13, 2025, 1:56 AM
- **Event:** User 'jtex' began copying multiple files to the desktop, including the creation of a file named 'tor-shopping-list.txt'.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The sequence of events indicates that user 'jtex' installed the Tor Browser on the device 'ehreat-hunt-lab' and configured Firefox to route traffic through the Tor network. Subsequently, 'jtex' created a file named 'tor-shopping-list.txt' on the desktop.
The use of Tor within an enterprise network can pose security risks, including bypassing network security controls and potential association with unauthorized activities. It's essential to monitor and control the use of such tools to maintain network integrity and compliance with organizational policies.


---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
