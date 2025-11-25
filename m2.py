import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import ssl, socket, idna, datetime, threading, requests, os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

# ========== Certificate Inspection ==========
def inspect_cert(host, port=443, timeout=5):
    try:
        host_idna = idna.encode(host)
    except Exception:
        host_idna = host.encode()

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    conn = socket.create_connection((host, port), timeout=timeout)
    sock = context.wrap_socket(conn, server_hostname=host)
    der_cert = sock.getpeercert(binary_form=True)
    sock.close()

    cert = x509.load_der_x509_certificate(der_cert, default_backend())
    info = {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "valid_from": cert.not_valid_before.isoformat(),
        "valid_to": cert.not_valid_after.isoformat(),
        "sha256": cert.fingerprint(hashes.SHA256()).hex(),
    }

    # quick validity checks
    now = datetime.datetime.utcnow()
    expired = now > cert.not_valid_after
    not_yet_valid = now < cert.not_valid_before
    validity = "VALID"
    if expired:
        validity = "EXPIRED"
    elif not_yet_valid:
        validity = "NOT YET VALID"

    info["validity_status"] = validity
    return info


# ========== File Downloader ==========
def download_file(url, dest_path, progress_callback):
    try:
        with requests.get(url, stream=True, timeout=10) as r:
            r.raise_for_status()
            total = int(r.headers.get("content-length", 0))
            downloaded = 0
            with open(dest_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total:
                            percent = int(downloaded * 100 / total)
                            progress_callback(percent)
        progress_callback(100)
        return True
    except Exception as e:
        messagebox.showerror("Download Error", f"Error downloading: {e}")
        return False


# ========== GUI ==========
class DownloadApp:
    def __init__(self, root):
        self.root = root
        root.title("NetSniff - Secure Downloader")
        root.geometry("650x450")
        root.resizable(False, False)

        ttk.Label(root, text="Enter HTTPS URL:", font=("Arial", 12, "bold")).pack(pady=5)
        self.url_entry = ttk.Entry(root, width=80)
        self.url_entry.pack(pady=5)

        ttk.Button(root, text="Inspect Certificate + Download", command=self.start_process).pack(pady=10)

        self.cert_box = tk.Text(root, height=12, width=80, wrap="word")
        self.cert_box.pack(pady=5)

        self.progress = ttk.Progressbar(root, length=600, mode="determinate")
        self.progress.pack(pady=10)

    def start_process(self):
        url = self.url_entry.get().strip()
        if not url.startswith("https://"):
            messagebox.showwarning("Invalid URL", "Please enter a valid HTTPS URL.")
            return

        # extract hostname for cert inspection
        host = url.split("://")[1].split("/")[0]
        self.cert_box.delete(1.0, tk.END)
        self.cert_box.insert(tk.END, f"Inspecting certificate for {host}...\n")
        self.root.update_idletasks()

        try:
            info = inspect_cert(host)
        except Exception as e:
            self.cert_box.insert(tk.END, f"\n❌ Error inspecting certificate: {e}\n")
            return

        # show certificate info
        self.cert_box.delete(1.0, tk.END)
        self.cert_box.insert(tk.END, "=== TLS Certificate Information ===\n")
        for k, v in info.items():
            self.cert_box.insert(tk.END, f"{k}: {v}\n")

        # Ask where to save file
        dest_path = filedialog.asksaveasfilename(
            title="Save Download As",
            initialfile=os.path.basename(url.split("?")[0]),
            defaultextension="",
        )
        if not dest_path:
            return

        # Run download in background thread
        threading.Thread(target=self._download_thread, args=(url, dest_path), daemon=True).start()

    def _download_thread(self, url, dest_path):
        self.progress["value"] = 0
        def update_prog(p):
            self.progress["value"] = p
            self.root.update_idletasks()

        ok = download_file(url, dest_path, update_prog)
        if ok:
            messagebox.showinfo("Download Complete", f"File saved to:\n{dest_path}")
        self.progress["value"] = 0


# ========== Run App ==========
if __name__ == "__main__":
    root = tk.Tk()
    app = DownloadApp(root)
    root.mainloop()
