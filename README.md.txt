FILE INTEGRITY MONITOR  
Version 1.0

PROJECT OVERVIEW

The File Integrity Monitor is a Python-based cybersecurity application designed to detect unauthorized or unexpected changes to files. The system uses SHA-256 cryptographic hashing to create a trusted baseline of monitored files and can compare the current state of those files against the baseline.

The project also includes real-time file system monitoring using the Watchdog library and a graphical user interface built with Tkinter.

The purpose of the application is to demonstrate how file integrity monitoring can be used as part of a defense-in-depth security strategy.

MAIN FEATURES

The File Integrity Monitor includes SHA-256 baseline creation, manual integrity scanning, real-time file monitoring, persistent security event logging, live event counters, duplicate-event filtering, and a graphical security dashboard.

The system can detect when files are added, modified, deleted, moved, or renamed inside the monitored directory.

REQUIREMENTS

Python 3

Python Watchdog library

Tkinter

Watchdog can be installed using the following command:

py -m pip install watchdog

Tkinter is included with most standard Python installations.

HOW TO RUN THE PROGRAM

Open a terminal in the FileIntegrityMonitor project folder.

Run the following command:

py fim_gui.py

The File Integrity Monitor graphical interface should open.

PROJECT FILES

fim_gui.py

This is the main application. It contains the graphical interface, SHA-256 hashing functions, baseline comparison logic, Watchdog monitoring, event handling, and logging functions.

baseline.json

This file stores the trusted SHA-256 hash values of files inside the monitored directory.

security.log

This file stores timestamped security events detected by the application.

monitored_files/

This folder contains the files that are being monitored for integrity changes.

backups/

This folder contains earlier development versions of the project.

USING THE APPLICATION

When the application opens, the user can create a trusted baseline using the Create Baseline button.

The Scan Now button performs a manual file integrity scan and compares the current files against the trusted SHA-256 baseline.

The Start Monitoring button activates real-time file monitoring. While monitoring is active, changes inside the monitored_files directory are detected immediately.

The Stop Monitoring button stops real-time monitoring.

The Open Monitored Folder button opens the monitored directory so that files can be viewed or tested.

The Open Security Log button opens the persistent security event log.

The Clear Event Display button clears the current live event display without deleting the saved security log.

EVENT TYPES

ADDED indicates that a new file was created inside the monitored directory.

MODIFIED indicates that the contents of an existing file changed.

DELETED indicates that a file was removed from the monitored directory.

MOVED indicates that a file was renamed or moved.

SYSTEM indicates an application-related event such as monitoring being started or stopped.

BASELINE indicates that a new trusted baseline was created.

SCAN indicates the result of a manual integrity scan.

BASIC DEMONSTRATION

To demonstrate the application, first place several test files inside the monitored_files directory.

Create a baseline using the Create Baseline button.

Run Scan Now to verify that no integrity violations are present.

Start real-time monitoring.

Modify one of the trusted files and observe the MODIFIED alert.

Create a new file and observe the ADDED alert.

Rename the new file and observe the MOVED alert.

Delete one of the trusted files and observe the DELETED alert.

Run Scan Now again to compare the current state of the monitored directory against the trusted baseline.

Open the Security Log to review the timestamped events recorded by the program.

SECURITY CONCEPTS DEMONSTRATED

This project demonstrates cryptographic hashing, file integrity verification, trusted baseline creation, real-time file system monitoring, event logging, security alerting, and defense-in-depth monitoring techniques.

TESTING STATUS

Version 1.0 has been tested successfully for baseline creation, clean integrity scanning, file modification detection, new file detection, file deletion detection, file movement and renaming detection, real-time monitoring, persistent event logging, event debouncing, application shutdown, and graphical interface functionality.