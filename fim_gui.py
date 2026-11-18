import hashlib
import json
import os
import queue
import time
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import messagebox, scrolledtext

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# -------------------------------------------------
# Project paths
# -------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
MONITORED_DIR = BASE_DIR / "monitored_files"
BASELINE_FILE = BASE_DIR / "baseline.json"
LOG_FILE = BASE_DIR / "security.log"

MONITORED_DIR.mkdir(exist_ok=True)


# -------------------------------------------------
# File hashing
# -------------------------------------------------

def calculate_hash(file_path):
    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:
            while chunk := file.read(4096):
                sha256.update(chunk)

        return sha256.hexdigest()

    except (PermissionError, OSError):
        return None


# -------------------------------------------------
# Directory scanning
# -------------------------------------------------

def scan_directory():
    hashes = {}

    for file_path in MONITORED_DIR.rglob("*"):
        if file_path.is_file():

            file_hash = calculate_hash(file_path)

            if file_hash:
                relative_path = str(
                    file_path.relative_to(MONITORED_DIR)
                )

                hashes[relative_path] = file_hash

    return hashes


# -------------------------------------------------
# Security logging
# -------------------------------------------------

def write_log(event_type, filename):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(LOG_FILE, "a", encoding="utf-8") as log:
        log.write(
            f"{timestamp} | {event_type} | {filename}\n"
        )


# -------------------------------------------------
# Real-time Watchdog event handler
# -------------------------------------------------

class SecurityEventHandler(FileSystemEventHandler):

    def __init__(self, event_queue):
        super().__init__()

        self.event_queue = event_queue

        # Used to prevent repeated events from appearing
        # several times during a single file save.
        self.last_events = {}

        self.debounce_seconds = 1.5


    def is_duplicate(self, event_type, file_path):
        """
        Prevent rapid duplicate events from appearing
        in the GUI.
        """

        current_time = time.monotonic()

        event_key = (
            event_type,
            str(file_path)
        )

        previous_time = self.last_events.get(
            event_key
        )

        if previous_time is not None:

            elapsed = (
                current_time
                - previous_time
            )

            if elapsed < self.debounce_seconds:
                return True

        self.last_events[event_key] = current_time

        return False


    def send_event(self, event_type, file_path):

        if self.is_duplicate(
            event_type,
            file_path
        ):
            return


        try:
            relative_path = str(
                Path(file_path).relative_to(
                    MONITORED_DIR
                )
            )

        except ValueError:
            relative_path = str(file_path)


        timestamp = datetime.now().strftime(
            "%H:%M:%S"
        )


        self.event_queue.put(
            (
                timestamp,
                event_type,
                relative_path
            )
        )


        write_log(
            event_type,
            relative_path
        )


    def on_created(self, event):

        if not event.is_directory:

            self.send_event(
                "ADDED",
                event.src_path
            )


    def on_modified(self, event):

        if not event.is_directory:

            self.send_event(
                "MODIFIED",
                event.src_path
            )


    def on_deleted(self, event):

        if not event.is_directory:

            self.send_event(
                "DELETED",
                event.src_path
            )


    def on_moved(self, event):

        if event.is_directory:
            return


        try:

            old_name = str(
                Path(
                    event.src_path
                ).relative_to(
                    MONITORED_DIR
                )
            )

            new_name = str(
                Path(
                    event.dest_path
                ).relative_to(
                    MONITORED_DIR
                )
            )


            description = (
                f"{old_name} -> {new_name}"
            )


        except ValueError:

            description = (
                f"{event.src_path} -> "
                f"{event.dest_path}"
            )


        if self.is_duplicate(
            "MOVED",
            description
        ):
            return


        timestamp = datetime.now().strftime(
            "%H:%M:%S"
        )


        self.event_queue.put(
            (
                timestamp,
                "MOVED",
                description
            )
        )


        write_log(
            "MOVED",
            description
        )


# -------------------------------------------------
# Main GUI Application
# -------------------------------------------------

class FIMApplication:

    def __init__(self, root):

        self.root = root

        self.root.title(
            "File Integrity Monitor"
        )

        self.root.geometry(
            "950x700"
        )

        self.root.minsize(
            800,
            600
        )


        self.observer = None

        self.monitoring = False

        self.event_queue = queue.Queue()


        # Session counters

        self.security_event_count = 0

        self.file_count = 0

        self.baseline_count = 0


        self.build_gui()

        self.refresh_statistics()

        self.process_event_queue()


        self.root.protocol(
            "WM_DELETE_WINDOW",
            self.close_program
        )


    # -------------------------------------------------
    # GUI Layout
    # -------------------------------------------------

    def build_gui(self):

        title = tk.Label(
            self.root,
            text="FILE INTEGRITY MONITOR",
            font=(
                "Segoe UI",
                22,
                "bold"
            )
        )

        title.pack(
            pady=(20, 4)
        )


        subtitle = tk.Label(
            self.root,
            text=(
                "Real-Time Security Monitoring "
                "Dashboard"
            ),
            font=(
                "Segoe UI",
                11
            )
        )

        subtitle.pack(
            pady=(0, 15)
        )


        # ---------------------------------------------
        # Status area
        # ---------------------------------------------

        status_frame = tk.Frame(
            self.root,
            bd=2,
            relief="groove"
        )

        status_frame.pack(
            fill="x",
            padx=20,
            pady=5
        )


        self.status_label = tk.Label(
            status_frame,
            text=(
                "● Monitoring Status: STOPPED"
            ),
            font=(
                "Segoe UI",
                12,
                "bold"
            ),
            fg="red"
        )

        self.status_label.pack(
            pady=(10, 4)
        )


        directory_label = tk.Label(
            status_frame,
            text=(
                f"Directory: "
                f"{MONITORED_DIR}"
            ),
            font=(
                "Segoe UI",
                9
            )
        )

        directory_label.pack(
            pady=(0, 10)
        )


        # ---------------------------------------------
        # Statistics
        # ---------------------------------------------

        statistics_frame = tk.Frame(
            self.root
        )

        statistics_frame.pack(
            fill="x",
            padx=20,
            pady=10
        )


        self.files_label = tk.Label(
            statistics_frame,
            text="Files Monitored: 0",
            font=(
                "Segoe UI",
                11,
                "bold"
            ),
            relief="groove",
            width=22,
            pady=8
        )

        self.files_label.pack(
            side="left",
            expand=True,
            padx=5
        )


        self.baseline_label = tk.Label(
            statistics_frame,
            text="Baseline Files: 0",
            font=(
                "Segoe UI",
                11,
                "bold"
            ),
            relief="groove",
            width=22,
            pady=8
        )

        self.baseline_label.pack(
            side="left",
            expand=True,
            padx=5
        )


        self.events_label = tk.Label(
            statistics_frame,
            text="Security Events: 0",
            font=(
                "Segoe UI",
                11,
                "bold"
            ),
            relief="groove",
            width=22,
            pady=8
        )

        self.events_label.pack(
            side="left",
            expand=True,
            padx=5
        )


        # ---------------------------------------------
        # Action buttons
        # ---------------------------------------------

        button_frame = tk.Frame(
            self.root
        )

        button_frame.pack(
            pady=10
        )


        baseline_button = tk.Button(
            button_frame,
            text="Create Baseline",
            width=17,
            command=self.create_baseline
        )

        baseline_button.grid(
            row=0,
            column=0,
            padx=5,
            pady=5
        )


        scan_button = tk.Button(
            button_frame,
            text="Scan Now",
            width=17,
            command=self.run_integrity_scan
        )

        scan_button.grid(
            row=0,
            column=1,
            padx=5,
            pady=5
        )


        self.start_button = tk.Button(
            button_frame,
            text="Start Monitoring",
            width=17,
            command=self.start_monitoring
        )

        self.start_button.grid(
            row=0,
            column=2,
            padx=5,
            pady=5
        )


        self.stop_button = tk.Button(
            button_frame,
            text="Stop Monitoring",
            width=17,
            command=self.stop_monitoring,
            state="disabled"
        )

        self.stop_button.grid(
            row=0,
            column=3,
            padx=5,
            pady=5
        )


        # ---------------------------------------------
        # Event heading
        # ---------------------------------------------

        event_label = tk.Label(
            self.root,
            text="LIVE SECURITY EVENTS",
            font=(
                "Segoe UI",
                12,
                "bold"
            )
        )

        event_label.pack(
            anchor="w",
            padx=20,
            pady=(10, 5)
        )


        # ---------------------------------------------
        # Live Event Viewer
        # ---------------------------------------------

        self.event_display = scrolledtext.ScrolledText(
            self.root,
            height=18,
            font=(
                "Consolas",
                10
            ),
            state="disabled"
        )

        self.event_display.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=(0, 10)
        )


        # Event colors

        self.event_display.tag_configure(
            "ADDED",
            foreground="green"
        )

        self.event_display.tag_configure(
            "MODIFIED",
            foreground="dark orange"
        )

        self.event_display.tag_configure(
            "DELETED",
            foreground="red"
        )

        self.event_display.tag_configure(
            "MOVED",
            foreground="purple"
        )

        self.event_display.tag_configure(
            "SYSTEM",
            foreground="blue"
        )

        self.event_display.tag_configure(
            "SCAN",
            foreground="gray"
        )

        self.event_display.tag_configure(
            "BASELINE",
            foreground="dark green"
        )


        # Column header

        self.event_display.config(
            state="normal"
        )

        self.event_display.insert(
            tk.END,
            (
                f"{'TIME':<10}"
                f"{'EVENT':<12}"
                f"FILE / DETAILS\n"
            )
        )

        self.event_display.insert(
            tk.END,
            "-" * 80 + "\n"
        )

        self.event_display.config(
            state="disabled"
        )


        # ---------------------------------------------
        # Bottom controls
        # ---------------------------------------------

        bottom_frame = tk.Frame(
            self.root
        )

        bottom_frame.pack(
            pady=(0, 15)
        )


        clear_button = tk.Button(
            bottom_frame,
            text="Clear Event Display",
            command=self.clear_events
        )

        clear_button.pack(
            side="left",
            padx=5
        )


        log_button = tk.Button(
            bottom_frame,
            text="Open Security Log",
            command=self.open_log
        )

        log_button.pack(
            side="left",
            padx=5
        )


        folder_button = tk.Button(
            bottom_frame,
            text="Open Monitored Folder",
            command=self.open_monitored_folder
        )

        folder_button.pack(
            side="left",
            padx=5
        )


    # -------------------------------------------------
    # Statistics
    # -------------------------------------------------

    def refresh_statistics(self):

        try:

            self.file_count = len(
                scan_directory()
            )

        except Exception:

            self.file_count = 0


        self.files_label.config(
            text=(
                f"Files Monitored: "
                f"{self.file_count}"
            )
        )


        if BASELINE_FILE.exists():

            try:

                with open(
                    BASELINE_FILE,
                    "r",
                    encoding="utf-8"
                ) as file:

                    baseline = json.load(
                        file
                    )

                self.baseline_count = len(
                    baseline
                )

            except (
                json.JSONDecodeError,
                OSError
            ):

                self.baseline_count = 0


        else:

            self.baseline_count = 0


        self.baseline_label.config(
            text=(
                f"Baseline Files: "
                f"{self.baseline_count}"
            )
        )


        self.events_label.config(
            text=(
                f"Security Events: "
                f"{self.security_event_count}"
            )
        )


    # -------------------------------------------------
    # Add event to GUI
    # -------------------------------------------------

    def add_event(
        self,
        timestamp,
        event_type,
        filename
    ):

        security_events = {
            "ADDED",
            "MODIFIED",
            "DELETED",
            "MOVED"
        }


        if event_type in security_events:

            self.security_event_count += 1


        message = (
            f"{timestamp:<10}"
            f"{event_type:<12}"
            f"{filename}\n"
        )


        self.event_display.config(
            state="normal"
        )


        self.event_display.insert(
            tk.END,
            message,
            event_type
        )


        self.event_display.see(
            tk.END
        )


        self.event_display.config(
            state="disabled"
        )


        self.refresh_statistics()


    # -------------------------------------------------
    # Process Watchdog queue
    # -------------------------------------------------

    def process_event_queue(self):

        try:

            while True:

                event = (
                    self.event_queue
                    .get_nowait()
                )


                timestamp = event[0]

                event_type = event[1]

                filename = event[2]


                self.add_event(
                    timestamp,
                    event_type,
                    filename
                )


        except queue.Empty:

            pass


        self.root.after(
            100,
            self.process_event_queue
        )


    # -------------------------------------------------
    # Create baseline
    # -------------------------------------------------

    def create_baseline(self):

        hashes = scan_directory()


        with open(
            BASELINE_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                hashes,
                file,
                indent=4
            )


        messagebox.showinfo(
            "Baseline Created",
            (
                "Baseline created successfully."
                f"\n\nFiles recorded: "
                f"{len(hashes)}"
            )
        )


        self.add_event(
            datetime.now().strftime(
                "%H:%M:%S"
            ),
            "BASELINE",
            (
                f"{len(hashes)} "
                "files recorded"
            )
        )


        self.refresh_statistics()


    # -------------------------------------------------
    # Manual integrity scan
    # -------------------------------------------------

    def run_integrity_scan(self):

        if not BASELINE_FILE.exists():

            messagebox.showwarning(
                "No Baseline",
                (
                    "Create a baseline before "
                    "running an integrity scan."
                )
            )

            return


        try:

            with open(
                BASELINE_FILE,
                "r",
                encoding="utf-8"
            ) as file:

                baseline = json.load(
                    file
                )


        except (
            json.JSONDecodeError,
            OSError
        ):

            messagebox.showerror(
                "Baseline Error",
                (
                    "The baseline file could "
                    "not be loaded."
                )
            )

            return


        current = scan_directory()


        baseline_names = set(
            baseline.keys()
        )


        current_names = set(
            current.keys()
        )


        added = (
            current_names
            - baseline_names
        )


        deleted = (
            baseline_names
            - current_names
        )


        common = (
            baseline_names
            & current_names
        )


        modified = []


        for filename in common:

            if (
                baseline[filename]
                != current[filename]
            ):

                modified.append(
                    filename
                )


        timestamp = datetime.now().strftime(
            "%H:%M:%S"
        )


        event_count = 0


        for filename in sorted(added):

            self.add_event(
                timestamp,
                "ADDED",
                filename
            )

            write_log(
                "ADDED",
                filename
            )

            event_count += 1


        for filename in sorted(deleted):

            self.add_event(
                timestamp,
                "DELETED",
                filename
            )

            write_log(
                "DELETED",
                filename
            )

            event_count += 1


        for filename in sorted(modified):

            self.add_event(
                timestamp,
                "MODIFIED",
                filename
            )

            write_log(
                "MODIFIED",
                filename
            )

            event_count += 1


        if event_count == 0:

            self.add_event(
                timestamp,
                "SCAN",
                (
                    "No integrity violations "
                    "detected"
                )
            )


        messagebox.showinfo(
            "Integrity Scan Complete",
            (
                "Security events detected: "
                f"{event_count}"
            )
        )


        self.refresh_statistics()


    # -------------------------------------------------
    # Start monitoring
    # -------------------------------------------------

    def start_monitoring(self):

        if self.monitoring:

            return


        handler = SecurityEventHandler(
            self.event_queue
        )


        self.observer = Observer()


        self.observer.schedule(
            handler,
            str(MONITORED_DIR),
            recursive=True
        )


        self.observer.start()


        self.monitoring = True


        self.status_label.config(
            text=(
                "● Monitoring Status: ACTIVE"
            ),
            fg="green"
        )


        self.start_button.config(
            state="disabled"
        )


        self.stop_button.config(
            state="normal"
        )


        self.add_event(
            datetime.now().strftime(
                "%H:%M:%S"
            ),
            "SYSTEM",
            (
                "Real-time monitoring "
                "started"
            )
        )


    # -------------------------------------------------
    # Stop monitoring
    # -------------------------------------------------

    def stop_monitoring(self):

        if (
            not self.monitoring
            or self.observer is None
        ):

            return


        self.observer.stop()

        self.observer.join()


        self.monitoring = False

        self.observer = None


        self.status_label.config(
            text=(
                "● Monitoring Status: STOPPED"
            ),
            fg="red"
        )


        self.start_button.config(
            state="normal"
        )


        self.stop_button.config(
            state="disabled"
        )


        self.add_event(
            datetime.now().strftime(
                "%H:%M:%S"
            ),
            "SYSTEM",
            (
                "Real-time monitoring "
                "stopped"
            )
        )


    # -------------------------------------------------
    # Clear event viewer
    # -------------------------------------------------

    def clear_events(self):

        self.event_display.config(
            state="normal"
        )


        self.event_display.delete(
            "1.0",
            tk.END
        )


        self.event_display.insert(
            tk.END,
            (
                f"{'TIME':<10}"
                f"{'EVENT':<12}"
                f"FILE / DETAILS\n"
            )
        )


        self.event_display.insert(
            tk.END,
            "-" * 80 + "\n"
        )


        self.event_display.config(
            state="disabled"
        )


    # -------------------------------------------------
    # Open security log
    # -------------------------------------------------

    def open_log(self):

        if not LOG_FILE.exists():

            messagebox.showinfo(
                "Security Log",
                "No security log exists yet."
            )

            return


        try:

            os.startfile(
                LOG_FILE
            )


        except Exception as error:

            messagebox.showerror(
                "Error",
                (
                    "Could not open log:"
                    f"\n{error}"
                )
            )


    # -------------------------------------------------
    # Open monitored folder
    # -------------------------------------------------

    def open_monitored_folder(self):

        try:

            os.startfile(
                MONITORED_DIR
            )


        except Exception as error:

            messagebox.showerror(
                "Error",
                (
                    "Could not open monitored "
                    f"folder:\n{error}"
                )
            )


    # -------------------------------------------------
    # Safely close program
    # -------------------------------------------------

    def close_program(self):

        if self.monitoring:

            self.stop_monitoring()


        self.root.destroy()


# -------------------------------------------------
# Start application
# -------------------------------------------------

if __name__ == "__main__":

    root = tk.Tk()

    app = FIMApplication(
        root
    )

    root.mainloop()