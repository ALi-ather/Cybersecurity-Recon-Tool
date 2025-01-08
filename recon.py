import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.ttk import Treeview, Style, Progressbar
import subprocess
import os

def run_command(command):
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        return "", str(e)

def validate_domain(domain):
    if not domain or "." not in domain:
        messagebox.showerror("Error", "Please enter a valid domain (e.g., example.com).")
        return False
    return True

def subdomain_enumeration(domain, output_folder):
    subdomains_file = os.path.join(output_folder, "subdomains.txt")
    command = ["subfinder", "-d", domain, "-o", subdomains_file]
    stdout, stderr = run_command(command)
    if stderr:
        messagebox.showerror("Error - Subfinder", stderr)
    return subdomains_file, stdout

def content_discovery(domain, wordlist, output_folder):
    content_file = os.path.join(output_folder, "content_discovery.txt")
    command = ["ffuf", "-w", wordlist, "-u", f"http://{domain}/FUZZ", "-o", content_file]
    stdout, stderr = run_command(command)
    if stderr:
        messagebox.showerror("Error - FFUF", stderr)
    return content_file, stdout

def waf_detection(domain):
    command = ["wafw00f", domain]
    stdout, stderr = run_command(command)
    if stderr:
        messagebox.showerror("Error - WAF Detection", stderr)
    return stdout

def run_recon():
    domain = domain_entry.get().strip()
    wordlist = wordlist_entry.get().strip() or DEFAULT_CONTENT_WORDLIST
    output_folder = output_folder_var.get()

    if not validate_domain(domain):
        return

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    results_tree.delete(*results_tree.get_children())

    try:
        progress_bar["value"] = 0
        root.update_idletasks()

        # 1. Subdomain Enumeration
        progress_label.config(text="Running Subdomain Enumeration...")
        subdomains_file, subfinder_output = subdomain_enumeration(domain, output_folder)
        results_tree.insert("", "end", values=("Subdomains File", subdomains_file))
        results_tree.insert("", "end", values=("Subfinder Output", subfinder_output[:100] + "..."))
        progress_bar.step(33)
        root.update_idletasks()

        # 2. WAF Detection
        progress_label.config(text="Detecting WAF...")
        waf_output = waf_detection(domain)
        results_tree.insert("", "end", values=("WAF Detection", waf_output[:100] + "..."))
        progress_bar.step(33)
        root.update_idletasks()

        # 3. Content Discovery
        progress_label.config(text="Running Content Discovery...")
        content_file, ffuf_output = content_discovery(domain, wordlist, output_folder)
        results_tree.insert("", "end", values=("Content Discovery File", content_file))
        results_tree.insert("", "end", values=("FFUF Output", ffuf_output[:100] + "..."))
        progress_bar.step(34)
        root.update_idletasks()

        progress_label.config(text="Tasks Completed Successfully!")
        messagebox.showinfo("Success", "Recon tasks completed successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

def browse_wordlist():
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    wordlist_entry.delete(0, tk.END)
    wordlist_entry.insert(0, file_path)

def browse_output_folder():
    folder_path = filedialog.askdirectory()
    output_folder_var.set(folder_path)

def configure_dark_theme():
    style = Style()
    style.theme_use("clam")
    style.configure("Treeview", background="#1e1e1e", foreground="white", fieldbackground="#1e1e1e")
    style.map("Treeview", background=[("selected", "#2b2b2b")])
    root.configure(bg="#1e1e1e")

DEFAULT_WORDLIST_DIR = "/usr/share/wordlists"
DEFAULT_CONTENT_WORDLIST = f"{DEFAULT_WORDLIST_DIR}/dirbuster/directory-list-2.3-medium.txt"

root = tk.Tk()
root.title("Cybersecurity Recon Tool")
configure_dark_theme()

output_folder_var = tk.StringVar(value="output")

# Input Domain
tk.Label(root, text="Target Domain:", font=("Arial", 12), bg="#1e1e1e", fg="green").grid(row=0, column=0, padx=10, pady=10)
domain_entry = tk.Entry(root, width=50, bg="#2b2b2b", fg="white")
domain_entry.grid(row=0, column=1, padx=10, pady=10)

# Input Wordlist
tk.Label(root, text="Wordlist:", font=("Arial", 12), bg="#1e1e1e", fg="green").grid(row=1, column=0, padx=10, pady=10)
wordlist_entry = tk.Entry(root, width=50, bg="#2b2b2b", fg="white")
wordlist_entry.grid(row=1, column=1, padx=10, pady=10)
tk.Button(root, text="Browse", command=browse_wordlist, bg="green", fg="white").grid(row=1, column=2, padx=10, pady=10)

# Output Folder Selection
tk.Label(root, text="Output Folder:", font=("Arial", 12), bg="#1e1e1e", fg="green").grid(row=2, column=0, padx=10, pady=10)
output_folder_entry = tk.Entry(root, textvariable=output_folder_var, width=50, bg="#2b2b2b", fg="white")
output_folder_entry.grid(row=2, column=1, padx=10, pady=10)
tk.Button(root, text="Browse", command=browse_output_folder, bg="green", fg="white").grid(row=2, column=2, padx=10, pady=10)

# Run Recon Button
tk.Button(root, text="Run Recon", command=run_recon, bg="green", fg="white", font=("Arial", 12)).grid(row=3, column=1, pady=20)

# Progress Bar
progress_label = tk.Label(root, text="", font=("Arial", 10), bg="#1e1e1e", fg="white")
progress_label.grid(row=4, column=0, columnspan=3, pady=5)
progress_bar = Progressbar(root, orient="horizontal", mode="determinate", length=400)
progress_bar.grid(row=5, column=0, columnspan=3, pady=10)

# Results Tree
results_tree = Treeview(root, columns=("Task", "Output"), show="headings", style="Treeview")
results_tree.heading("Task", text="Task")
results_tree.heading("Output", text="Output")
results_tree.grid(row=6, column=0, columnspan=3, padx=10, pady=10)

root.mainloop()
