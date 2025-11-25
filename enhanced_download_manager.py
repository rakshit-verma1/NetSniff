import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import datetime
import threading
import urllib.request
import os
import hashlib

class EnhancedDownloadManagerTab(ttk.Frame):
    def __init__(self, master, security_manager):
        super().__init__(master)
        self.security_manager = security_manager
        self.active_downloads = {}  # Store active download threads
        self.setup_ui()
        self.pack(fill="both", expand=True, padx=5, pady=5)
    
    def setup_ui(self):
        # Title
        title_frame = ttk.Frame(self)
        title_frame.pack(fill="x", pady=10)
        
        ttk.Label(title_frame, text="🔒 Secure Download Manager with Real-time Scanning", 
                  font=("Arial", 12, "bold")).pack(side="left", padx=10)
        
        ttk.Button(title_frame, text="➕ Add Download", 
                   command=self.show_add_download_dialog).pack(side="right", padx=10)
        
        # Statistics
        stats_frame = ttk.LabelFrame(self, text=" Download Statistics ", padding=10)
        stats_frame.pack(fill="x", padx=10, pady=5)
        
        self.total_downloads_var = tk.StringVar(value="Total: 0")
        self.active_downloads_var = tk.StringVar(value="Active: 0")
        self.blocked_downloads_var = tk.StringVar(value="Blocked: 0")
        self.safe_downloads_var = tk.StringVar(value="Safe: 0")
        
        ttk.Label(stats_frame, textvariable=self.total_downloads_var, font=("Arial", 10)).pack(side="left", padx=10)
        ttk.Label(stats_frame, textvariable=self.active_downloads_var, foreground="#2196F3", font=("Arial", 10, "bold")).pack(side="left", padx=10)
        ttk.Label(stats_frame, textvariable=self.blocked_downloads_var, foreground="#d32f2f", font=("Arial", 10)).pack(side="left", padx=10)
        ttk.Label(stats_frame, textvariable=self.safe_downloads_var, foreground="#2e7d32", font=("Arial", 10)).pack(side="left", padx=10)
        
        # Create notebook for different views
        self.download_notebook = ttk.Notebook(self)
        self.download_notebook.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Tab 1: Detected Downloads (from network traffic)
        detected_frame = ttk.Frame(self.download_notebook)
        self.download_notebook.add(detected_frame, text="📡 Detected Downloads")
        self.setup_detected_tab(detected_frame)
        
        # Tab 2: Manual Downloads (user initiated)
        manual_frame = ttk.Frame(self.download_notebook)
        self.download_notebook.add(manual_frame, text="⬇️ My Downloads")
        self.setup_manual_tab(manual_frame)
        
        # Control buttons
        control_frame = ttk.Frame(self)
        control_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(control_frame, text="🔄 Refresh", command=self.refresh_all).pack(side="left", padx=5)
        ttk.Button(control_frame, text="🗑️ Clear Detected", command=self.clear_detected_list).pack(side="left", padx=5)
        ttk.Button(control_frame, text="📁 Open Downloads Folder", command=self.open_downloads_folder).pack(side="left", padx=5)
        
        # Info label
        note_label = ttk.Label(self, 
                              text="💡 Detected downloads are captured from network traffic. Use 'Add Download' to safely download and scan files.",
                              font=("Arial", 8), foreground="gray")
        note_label.pack(pady=5)
    
    def setup_detected_tab(self, parent):
        """Setup tab for network-detected downloads"""
        table_frame = ttk.Frame(parent)
        table_frame.pack(fill="both", expand=True, pady=5)
        
        columns = ("Time", "Filename", "URL", "Status", "VT Score", "Safety", "Action")
        self.detected_table = ttk.Treeview(table_frame, columns=columns, show="headings", height=18)
        
        column_widths = (80, 150, 350, 100, 80, 100, 120)
        for col, width in zip(columns, column_widths):
            self.detected_table.heading(col, text=col, anchor="center")
            self.detected_table.column(col, width=width, anchor="center")
        
        self.detected_table.tag_configure("safe", background="#e8f5e8")
        self.detected_table.tag_configure("blocked", background="#ffe6e6", foreground="#d32f2f")
        self.detected_table.tag_configure("scanning", background="#fff9e6")
        
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.detected_table.yview)
        self.detected_table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.detected_table.pack(side="left", fill="both", expand=True)
        
        # Bind double-click to download
        self.detected_table.bind("<Double-1>", self.on_detected_double_click)
        
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill="x", pady=5)
        
        ttk.Button(button_frame, text="⬇️ Download Selected", 
                  command=self.download_selected_detected).pack(side="left", padx=5)
        ttk.Label(button_frame, text="(Double-click to download)", 
                 font=("Arial", 8), foreground="gray").pack(side="left", padx=5)
    
    def setup_manual_tab(self, parent):
        """Setup tab for user-initiated downloads"""
        table_frame = ttk.Frame(parent)
        table_frame.pack(fill="both", expand=True, pady=5)
        
        columns = ("Time", "Filename", "URL", "Progress", "Speed", "Status", "Safety", "Action")
        self.manual_table = ttk.Treeview(table_frame, columns=columns, show="headings", height=18)
        
        column_widths = (80, 150, 300, 100, 80, 100, 100, 100)
        for col, width in zip(columns, column_widths):
            self.manual_table.heading(col, text=col, anchor="center")
            self.manual_table.column(col, width=width, anchor="center")
        
        self.manual_table.tag_configure("downloading", background="#e3f2fd", foreground="#1976D2")
        self.manual_table.tag_configure("completed", background="#e8f5e8", foreground="#2e7d32")
        self.manual_table.tag_configure("failed", background="#ffe6e6", foreground="#d32f2f")
        self.manual_table.tag_configure("paused", background="#fff9e6")
        self.manual_table.tag_configure("blocked", background="#ffcdd2", foreground="#c62828")
        
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.manual_table.yview)
        self.manual_table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.manual_table.pack(side="left", fill="both", expand=True)
        
        # Bind right-click for context menu
        self.manual_table.bind("<Button-3>", self.show_context_menu)
        
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill="x", pady=5)
        
        ttk.Button(button_frame, text="⏸️ Pause", 
                  command=self.pause_selected).pack(side="left", padx=5)
        ttk.Button(button_frame, text="▶️ Resume", 
                  command=self.resume_selected).pack(side="left", padx=5)
        ttk.Button(button_frame, text="❌ Cancel", 
                  command=self.cancel_selected).pack(side="left", padx=5)
        ttk.Button(button_frame, text="📁 Open File", 
                  command=self.open_selected_file).pack(side="left", padx=5)
    
    def show_add_download_dialog(self):
        """Show dialog to add a new download"""
        dialog = tk.Toplevel(self)
        dialog.title("Add New Download")
        dialog.geometry("600x400")
        dialog.transient(self)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (600 // 2)
        y = (dialog.winfo_screenheight() // 2) - (400 // 2)
        dialog.geometry(f"+{x}+{y}")
        
        main_frame = ttk.Frame(dialog, padding=20)
        main_frame.pack(fill="both", expand=True)
        
        ttk.Label(main_frame, text="Download URL:", font=("Arial", 10, "bold")).pack(anchor="w", pady=(0, 5))
        
        url_frame = ttk.Frame(main_frame)
        url_frame.pack(fill="x", pady=(0, 15))
        
        url_entry = ttk.Entry(url_frame, font=("Arial", 10))
        url_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        ttk.Button(url_frame, text="📋 Paste", 
                  command=lambda: url_entry.insert(0, dialog.clipboard_get())).pack(side="right")
        
        ttk.Label(main_frame, text="Save Location:", font=("Arial", 10, "bold")).pack(anchor="w", pady=(10, 5))
        
        path_frame = ttk.Frame(main_frame)
        path_frame.pack(fill="x", pady=(0, 15))
        
        default_path = os.path.join(os.path.expanduser("~"), "Downloads")
        path_var = tk.StringVar(value=default_path)
        
        path_entry = ttk.Entry(path_frame, textvariable=path_var, font=("Arial", 10))
        path_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        def browse_folder():
            folder = filedialog.askdirectory(initialdir=path_var.get())
            if folder:
                path_var.set(folder)
        
        ttk.Button(path_frame, text="📁 Browse", command=browse_folder).pack(side="right")
        
        # Security options
        security_frame = ttk.LabelFrame(main_frame, text=" Security Options ", padding=10)
        security_frame.pack(fill="x", pady=(10, 15))
        
        scan_var = tk.BooleanVar(value=True)
        auto_block_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(security_frame, text="🛡️ Scan with VirusTotal before download", 
                       variable=scan_var).pack(anchor="w", pady=2)
        ttk.Checkbutton(security_frame, text="🚫 Auto-block if threat detected (>30% malicious)", 
                       variable=auto_block_var).pack(anchor="w", pady=2)
        
        # Info box
        info_frame = ttk.Frame(main_frame)
        info_frame.pack(fill="both", expand=True, pady=(10, 15))
        
        info_text = tk.Text(info_frame, height=6, wrap="word", font=("Arial", 9), 
                           bg="#f5f5f5", relief="flat", padx=10, pady=10)
        info_text.pack(fill="both", expand=True)
        info_text.insert("1.0", 
            "ℹ️ Security Features:\n\n"
            "• URL will be scanned with VirusTotal API before download\n"
            "• File hash will be checked against known malware signatures\n"
            "• Download will be monitored in real-time\n"
            "• Safe files will be saved to your chosen location")
        info_text.config(state="disabled")
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill="x", pady=(10, 0))
        
        def start_download():
            url = url_entry.get().strip()
            if not url:
                messagebox.showwarning("Invalid URL", "Please enter a valid URL")
                return
            
            if not url.startswith(("http://", "https://")):
                messagebox.showwarning("Invalid URL", "URL must start with http:// or https://")
                return
            
            save_path = path_var.get()
            if not os.path.exists(save_path):
                messagebox.showerror("Invalid Path", "Save location does not exist")
                return
            
            dialog.destroy()
            self.initiate_download(url, save_path, scan_var.get(), auto_block_var.get())
        
        ttk.Button(button_frame, text="⬇️ Start Download", 
                  command=start_download).pack(side="right", padx=(5, 0))
        ttk.Button(button_frame, text="❌ Cancel", 
                  command=dialog.destroy).pack(side="right")
    
    def initiate_download(self, url, save_path, scan_first, auto_block):
        """Start a new download with security checks"""
        try:
            filename = url.split('/')[-1].split('?')[0] or "download"
            
            # Ensure filename has extension
            if '.' not in filename:
                filename += '.bin'
            
            full_path = os.path.join(save_path, filename)
            
            print(f"\n{'='*60}")
            print(f"Initiating download:")
            print(f"  URL: {url}")
            print(f"  Filename: {filename}")
            print(f"  Save Path: {full_path}")
            print(f"  Scan First: {scan_first}")
            print(f"  Auto Block: {auto_block}")
            print(f"{'='*60}\n")
            
            # Check if file exists
            if os.path.exists(full_path):
                response = messagebox.askyesno("File Exists", 
                                              f"File '{filename}' already exists. Overwrite?")
                if not response:
                    print("Download cancelled: File exists")
                    return
            
            download_id = datetime.datetime.now().strftime("%Y%m%d%H%M%S%f")
            
            download_info = {
                "id": download_id,
                "url": url,
                "filename": filename,
                "save_path": full_path,
                "time": datetime.datetime.now().strftime("%H:%M:%S"),
                "progress": "0%",
                "speed": "0 KB/s",
                "status": "Initializing...",
                "safety": "Checking...",
                "scan_first": scan_first,
                "auto_block": auto_block,
                "paused": False,
                "cancelled": False
            }
            
            self.security_manager.add_manual_download(download_info)
            self.refresh_manual_downloads()
            
            print(f"Download info added to security manager")
            print(f"Starting download thread...")
            
            # Start download in separate thread
            thread = threading.Thread(target=self.download_file_thread, 
                                     args=(download_info,), daemon=True)
            self.active_downloads[download_id] = thread
            thread.start()
            
            print(f"Download thread started successfully")
            
            messagebox.showinfo("Download Started", 
                               f"Download started: {filename}\n\nMonitor progress in 'My Downloads' tab.")
        
        except Exception as e:
            error_msg = f"Failed to initiate download: {e}"
            print(f"ERROR: {error_msg}")
            import traceback
            traceback.print_exc()
            messagebox.showerror("Download Error", error_msg)
    
    def download_file_thread(self, download_info):
        """Download file in background thread with security checks"""
        try:
            # Step 1: Security scan if enabled
            if download_info["scan_first"]:
                download_info["status"] = "Scanning URL..."
                self.after(0, self.refresh_manual_downloads)
                
                try:
                    scan_result = self.security_manager.scan_url_virustotal(download_info["url"])
                    
                    # Check if there's an error (like no API key)
                    if "error" in scan_result:
                        print(f"VirusTotal scan warning: {scan_result['error']}")
                        download_info["safety"] = "⚠️ Not scanned"
                    elif not scan_result.get("safe", True) and download_info["auto_block"]:
                        malicious_count = scan_result.get("malicious", 0)
                        total = scan_result.get("total", 1)
                        percentage = (malicious_count / total * 100) if total > 0 else 0
                        
                        if percentage > 30:
                            download_info["status"] = "BLOCKED"
                            download_info["safety"] = f"⚠️ {malicious_count}/{total} flagged"
                            self.after(0, self.refresh_manual_downloads)
                            self.after(0, lambda: messagebox.showwarning("Download Blocked",
                                f"Download blocked for security reasons:\n\n"
                                f"• {malicious_count} out of {total} scanners flagged this URL\n"
                                f"• Threat level: {percentage:.1f}%\n\n"
                                f"This file may contain malware."))
                            return
                    else:
                        download_info["safety"] = "✓ Safe" if scan_result.get("safe", True) else "⚠️ Suspicious"
                except Exception as scan_error:
                    print(f"VirusTotal scan error: {scan_error}")
                    download_info["safety"] = "⚠️ Not scanned"
            
            # Step 2: Download file
            download_info["status"] = "Downloading..."
            self.after(0, self.refresh_manual_downloads)
            
            print(f"Starting download: {download_info['url']}")
            print(f"Saving to: {download_info['save_path']}")
            
            def progress_callback(block_count, block_size, total_size):
                if download_info.get("cancelled", False):
                    raise Exception("Download cancelled")
                
                if download_info.get("paused", False):
                    return
                
                downloaded = block_count * block_size
                if total_size > 0:
                    progress = min(100, (downloaded / total_size) * 100)
                    download_info["progress"] = f"{progress:.1f}%"
                    
                    # Calculate speed (rough estimate)
                    speed_kb = (downloaded / 1024) / max(1, block_count * 0.1)
                    if speed_kb > 1024:
                        download_info["speed"] = f"{speed_kb/1024:.1f} MB/s"
                    else:
                        download_info["speed"] = f"{speed_kb:.1f} KB/s"
                    
                    if block_count % 10 == 0:  # Update UI every 10 blocks
                        self.after(0, self.refresh_manual_downloads)
            
            try:
                # Create directory if it doesn't exist
                os.makedirs(os.path.dirname(download_info['save_path']), exist_ok=True)
                
                # Download the file
                urllib.request.urlretrieve(download_info["url"], 
                                          download_info["save_path"], 
                                          progress_callback)
                
                print(f"Download completed: {download_info['save_path']}")
            except Exception as download_error:
                print(f"Download error: {download_error}")
                raise
            
            # Step 3: Verify downloaded file
            download_info["status"] = "Verifying..."
            download_info["progress"] = "100%"
            self.after(0, self.refresh_manual_downloads)
            
            # Check if file exists
            if not os.path.exists(download_info["save_path"]):
                raise Exception("File not found after download")
            
            # Calculate file hash
            try:
                file_hash = self.calculate_file_hash(download_info["save_path"])
                download_info["file_hash"] = file_hash
                print(f"File hash: {file_hash}")
            except Exception as hash_error:
                print(f"Hash calculation error: {hash_error}")
                download_info["file_hash"] = "N/A"
            
            # Step 4: Complete
            download_info["status"] = "✓ Completed"
            download_info["progress"] = "100%"
            download_info["speed"] = "-"
            self.after(0, self.refresh_manual_downloads)
            self.after(0, self.update_statistics)
            
            print(f"Download successful: {download_info['filename']}")
            
            self.after(0, lambda: messagebox.showinfo("Download Complete",
                f"Download completed successfully!\n\n"
                f"File: {download_info['filename']}\n"
                f"Location: {download_info['save_path']}\n"
                f"Safety: {download_info.get('safety', 'Unknown')}"))
            
        except Exception as e:
            error_msg = str(e)
            print(f"Download failed: {error_msg}")
            
            if "cancelled" in error_msg.lower():
                download_info["status"] = "Cancelled"
            else:
                download_info["status"] = f"Failed: {error_msg[:50]}"
            download_info["safety"] = "N/A"
            download_info["speed"] = "-"
            self.after(0, self.refresh_manual_downloads)
            
            if "cancelled" not in error_msg.lower():
                self.after(0, lambda: messagebox.showerror("Download Failed",
                    f"Download failed:\n\n{error_msg}\n\n"
                    f"Please check your internet connection and try again."))
    
    def calculate_file_hash(self, filepath):
        """Calculate SHA256 hash of file"""
        try:
            sha256 = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except:
            return "N/A"
    
    def process_packet(self, packet_info):
        """Called when new packet is detected"""
        self.refresh_detected_downloads()
    
    def refresh_all(self):
        """Refresh both tabs"""
        self.refresh_detected_downloads()
        self.refresh_manual_downloads()
        self.update_statistics()
    
    def refresh_detected_downloads(self):
        """Refresh network-detected downloads"""
        self.detected_table.delete(*self.detected_table.get_children())
        
        downloads = self.security_manager.get_downloads()
        
        for download in downloads:
            safety = "✓ SAFE" if download.get("safe", True) else "✗ BLOCKED"
            tag = "safe" if download.get("safe", True) else "blocked"
            vt_score = f"{download.get('vt_score', 0):.1f}%"
            
            self.detected_table.insert("", 0, values=(
                download["time"],
                download["filename"][:30],
                download["url"][:45] + "..." if len(download["url"]) > 45 else download["url"],
                download["status"],
                vt_score,
                safety,
                "Double-click"
            ), tags=(tag,))
    
    def refresh_manual_downloads(self):
        """Refresh user-initiated downloads"""
        self.manual_table.delete(*self.manual_table.get_children())
        
        manual_downloads = self.security_manager.get_manual_downloads()
        
        for download in manual_downloads:
            status = download.get("status", "Unknown")
            
            if "Downloading" in status:
                tag = "downloading"
            elif "Completed" in status:
                tag = "completed"
            elif "Failed" in status or "Error" in status:
                tag = "failed"
            elif "BLOCKED" in status:
                tag = "blocked"
            elif download.get("paused", False):
                tag = "paused"
            else:
                tag = "downloading"
            
            self.manual_table.insert("", 0, values=(
                download["time"],
                download["filename"][:25],
                download["url"][:40] + "..." if len(download["url"]) > 40 else download["url"],
                download.get("progress", "0%"),
                download.get("speed", "-"),
                status,
                download.get("safety", "Checking..."),
                "Right-click"
            ), tags=(tag,))
    
    def update_statistics(self):
        """Update statistics display"""
        detected = len(self.security_manager.get_downloads())
        manual = len(self.security_manager.get_manual_downloads())
        
        active = len([d for d in self.security_manager.get_manual_downloads() 
                     if "Downloading" in d.get("status", "")])
        
        blocked_detected = sum(1 for d in self.security_manager.get_downloads() 
                              if not d.get("safe", True))
        blocked_manual = sum(1 for d in self.security_manager.get_manual_downloads() 
                            if "BLOCKED" in d.get("status", ""))
        
        safe = (detected + manual) - (blocked_detected + blocked_manual)
        
        self.total_downloads_var.set(f"Total: {detected + manual}")
        self.active_downloads_var.set(f"Active: {active}")
        self.blocked_downloads_var.set(f"Blocked: {blocked_detected + blocked_manual}")
        self.safe_downloads_var.set(f"Safe: {safe}")
    
    def on_detected_double_click(self, event):
        """Handle double-click on detected download"""
        self.download_selected_detected()
    
    def download_selected_detected(self):
        """Download selected detected file"""
        selection = self.detected_table.selection()
        if not selection:
            messagebox.showinfo("No Selection", "Please select a download to download")
            return
        
        item = self.detected_table.item(selection[0])
        values = item["values"]
        url = values[2]
        
        # Remove "..." if truncated
        if url.endswith("..."):
            # Get full URL from security manager
            downloads = self.security_manager.get_downloads()
            for d in downloads:
                if d["filename"] == values[1]:
                    url = d["url"]
                    break
        
        # Ask for save location
        default_path = os.path.join(os.path.expanduser("~"), "Downloads")
        save_path = filedialog.askdirectory(initialdir=default_path, 
                                           title="Select Save Location")
        
        if save_path:
            self.initiate_download(url, save_path, scan_first=True, auto_block=True)
    
    def pause_selected(self):
        """Pause selected download"""
        selection = self.manual_table.selection()
        if not selection:
            return
        
        # TODO: Implement pause functionality
        messagebox.showinfo("Feature", "Pause functionality coming soon!")
    
    def resume_selected(self):
        """Resume selected download"""
        selection = self.manual_table.selection()
        if not selection:
            return
        
        # TODO: Implement resume functionality
        messagebox.showinfo("Feature", "Resume functionality coming soon!")
    
    def cancel_selected(self):
        """Cancel selected download"""
        selection = self.manual_table.selection()
        if not selection:
            return
        
        response = messagebox.askyesno("Cancel Download", 
                                      "Are you sure you want to cancel this download?")
        if response:
            # TODO: Implement cancel functionality
            messagebox.showinfo("Cancelled", "Download cancelled")
    
    def open_selected_file(self):
        """Open selected downloaded file"""
        selection = self.manual_table.selection()
        if not selection:
            messagebox.showinfo("No Selection", "Please select a completed download")
            return
        
        item = self.manual_table.item(selection[0])
        values = item["values"]
        filename = values[1]
        
        # Find file path
        manual_downloads = self.security_manager.get_manual_downloads()
        for download in manual_downloads:
            if download["filename"] == filename and "Completed" in download.get("status", ""):
                filepath = download["save_path"]
                if os.path.exists(filepath):
                    os.startfile(filepath) if os.name == 'nt' else os.system(f'xdg-open "{filepath}"')
                    return
        
        messagebox.showwarning("File Not Found", "Downloaded file not found or download not completed")
    
    def show_context_menu(self, event):
        """Show context menu on right-click"""
        # TODO: Implement context menu
        pass
    
    def clear_detected_list(self):
        """Clear detected downloads list"""
        response = messagebox.askyesno("Clear List", 
                                      "Clear all detected downloads from the list?")
        if response:
            self.detected_table.delete(*self.detected_table.get_children())
    
    def open_downloads_folder(self):
        """Open default downloads folder"""
        default_path = os.path.join(os.path.expanduser("~"), "Downloads")
        if os.path.exists(default_path):
            os.startfile(default_path) if os.name == 'nt' else os.system(f'xdg-open "{default_path}"')
        else:
            messagebox.showwarning("Folder Not Found", "Downloads folder not found")