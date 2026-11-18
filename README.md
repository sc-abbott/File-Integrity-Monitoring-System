# File Integrity Monitor

A Python-based cybersecurity application that detects unauthorized or unexpected changes to files using **SHA-256 hashing**, **real-time file monitoring**, and a **Tkinter graphical dashboard**.

## Overview

The File Integrity Monitor was developed as an individual cybersecurity project to demonstrate how file integrity monitoring can be used to identify suspicious changes to files.

The application creates a trusted baseline of monitored files using SHA-256 hashes and compares the current state of those files against the baseline. It also uses the Python Watchdog library to detect file system activity in real time.

The completed system can detect when files are added, modified, deleted, renamed, or moved inside the monitored directory.

## Features

- SHA-256 trusted baseline creation
- Manual file integrity scanning
- Real-time file system monitoring
- Detection of added files
- Detection of modified files
- Detection of deleted files
- Detection of renamed or moved files
- Persistent security event logging
- Duplicate-event filtering
- Live file and event counters
- Color-coded security alerts
- Tkinter graphical user interface
- Start and stop monitoring controls
- Direct access to the monitored directory and security log

## Technologies Used

- **Python 3**
- **Tkinter** for the graphical interface
- **Watchdog** for real-time file system monitoring
- **hashlib** for SHA-256 hashing
- **JSON** for baseline storage
- **pathlib** for file and directory handling

## Requirements

Python 3 must be installed.

Install the Watchdog dependency with:

```bash
py -m pip install watchdog
```

The project was developed using:

```text
watchdog==6.0.0
```

Tkinter is included with most standard Python installations.

## Running the Application

Open a terminal inside the project directory and run:

```bash
py fim_gui.py
```

The File Integrity Monitor dashboard should open.

## Project Structure

```text
Abbott_Project_FileIntegrityMonitor/
│
├── fim_gui.py
├── README.md
├── requirements.txt
├── .gitignore
│
├── monitored_files/
│   └── Sample files used for monitoring and testing
│
└── Figures/
    ├── File Integrity Monitor dashboard screenshot
    └── System architecture diagram
```

### Main Files

**`fim_gui.py`**  
Contains the main File Integrity Monitor application, including the graphical interface, hashing functions, integrity scanning, Watchdog monitoring, event handling, and logging.

**`requirements.txt`**  
Lists the external Python dependency required by the project.

**`monitored_files/`**  
Contains the files monitored by the application.

**`Figures/`**  
Contains screenshots and diagrams documenting the completed project.

The application generates additional files during normal use, including the trusted baseline and security event log.

## How the System Works

The application uses two complementary methods of file monitoring.

### SHA-256 Integrity Verification

When the user selects **Create Baseline**, the program scans the monitored directory and calculates a SHA-256 hash for each file. These values represent the trusted state of the files.

When **Scan Now** is selected, the application calculates the current hashes and compares them against the baseline.

A different hash indicates that a file has been modified. The program also compares filenames to identify newly added or deleted files.

### Real-Time Monitoring

When **Start Monitoring** is selected, Watchdog begins observing the monitored directory.

The system can immediately detect:

```text
ADDED
MODIFIED
DELETED
MOVED
```

Detected events are displayed in the graphical dashboard and recorded in the security log.

## Graphical Dashboard

The Tkinter dashboard provides controls for:

- Creating a trusted baseline
- Running a manual integrity scan
- Starting real-time monitoring
- Stopping real-time monitoring
- Opening the monitored directory
- Opening the security event log
- Clearing the live event display

The dashboard also displays the current monitoring status, number of monitored files, number of baseline files, and number of detected security events.

## Event Types

| Event | Description |
|---|---|
| `ADDED` | A new file was created |
| `MODIFIED` | The contents of an existing file changed |
| `DELETED` | A file was removed |
| `MOVED` | A file was renamed or moved |
| `SYSTEM` | Monitoring was started or stopped |
| `BASELINE` | A trusted baseline was created |
| `SCAN` | A manual integrity scan was completed |

The live dashboard uses different colors to make event types easier to identify.

## Basic Demonstration

A typical demonstration of the project follows this sequence:

1. Place several test files inside `monitored_files`.
2. Launch the application.
3. Select **Create Baseline**.
4. Run **Scan Now** and confirm that no integrity violations are detected.
5. Select **Start Monitoring**.
6. Modify a trusted file and observe the `MODIFIED` event.
7. Create a new file and observe the `ADDED` event.
8. Rename the new file and observe the `MOVED` event.
9. Delete a trusted file and observe the `DELETED` event.
10. Run **Scan Now** again to compare the current files against the trusted SHA-256 baseline.
11. Open the security log to review the recorded events.
12. Select **Stop Monitoring**.

## Testing

Version 1.0 was successfully tested for:

- Baseline creation
- Clean integrity scanning
- SHA-256 modification detection
- New file detection
- Deleted file detection
- File movement and rename detection
- Real-time monitoring
- Persistent event logging
- Duplicate-event filtering
- File and event counters
- Monitoring start and stop controls
- Normal application shutdown

## Security Concepts Demonstrated

This project demonstrates several cybersecurity concepts, including:

- File integrity monitoring
- Cryptographic hashing
- Trusted baselines
- Real-time security monitoring
- Security event logging
- Defense in depth
- Alert filtering
- File system event detection

## Limitations

The application detects changes to files but does not automatically determine whether those changes are malicious.

The trusted baseline is stored locally, and the current version focuses on monitoring a designated project directory rather than an entire operating system.

## Future Improvements

Possible future improvements include database-backed event storage, user-selected monitoring directories, desktop or email notifications, protected or digitally signed baselines, event filtering and searching, severity levels, report exporting, and packaging the application as a standalone Windows executable.

## Project Status

**Version 1.0: Complete**

The final implementation successfully combines SHA-256 integrity verification, real-time Watchdog monitoring, graphical security alerts, persistent event logging, event debouncing, and live system statistics.
