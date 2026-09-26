import tkinter as tk
from tkinter import filedialog, messagebox

SUSPICIOUS_KEYWORDS = {"eval", "system", "exec", "payload", "cmd"}

KNOWN_THREAT_DATABASE = {
    861545: "EICAR.Standard.TestThreat",
    104729: "Trojan.Script.Basic",
    542891: "Backdoor.Pattern.VariantA"
}


def is_prime(number):
    if number <= 1:
        return False
    divisor = 2
    while divisor * divisor <= number:
        if number % divisor == 0:
            return False
        divisor = divisor + 1
    return True


def power_modulo(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp = exp // 2
    return result


def compute_file_hash(char_list):
    prime_multiplier = 31
    modulus = 1000003
    current_hash = 0
    for ch in char_list:
        num_val = ord(ch)
        current_hash = (current_hash * prime_multiplier + num_val) % modulus
    return current_hash


def reverse_character_list(arr):
    start = 0
    end = len(arr) - 1
    while start < end:
        arr[start], arr[end] = arr[end], arr[start]
        start = start + 1
        end = end - 1
    return arr


def remove_duplicates_from_list(arr):
    unique_items = []
    for item in arr:
        if item not in unique_items:
            unique_items.append(item)
    return unique_items


def find_maximum_frequency(frequency_dict):
    max_count = 0
    dominant_char = ""
    for char, count in frequency_dict.items():
        if count > max_count:
            max_count = count
            dominant_char = char
    return (dominant_char, max_count)


def partition_file_bytes(ascii_values):
    printable = []
    non_printable = []
    for val in ascii_values:
        if val >= 32 and val <= 126:
            printable.append(val)
        else:
            non_printable.append(val)
    return (printable, non_printable)


def analyze_file_content(raw_text):
    content_array = list(raw_text)
    total_length = len(content_array)

    if total_length == 0:
        return None

    freq_map = {}
    ascii_list = []
    for ch in content_array:
        ascii_list.append(ord(ch))
        if ch in freq_map:
            freq_map[ch] = freq_map[ch] + 1
        else:
            freq_map[ch] = 1

    printable_chars, non_printable_chars = partition_file_bytes(ascii_list)
    most_common_char, highest_count = find_maximum_frequency(freq_map)
    signature = compute_file_hash(content_array)
    is_sig_prime = is_prime(signature)

    matched_flags = []
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in raw_text:
            matched_flags.append(keyword)

    unique_flags = remove_duplicates_from_list(matched_flags)

    return {
        "length": total_length,
        "printable": len(printable_chars),
        "non_printable": len(non_printable_chars),
        "dominant_char": repr(most_common_char),
        "dominant_count": highest_count,
        "signature": signature,
        "is_prime": is_sig_prime,
        "database_match": KNOWN_THREAT_DATABASE.get(signature, None),
        "flags": unique_flags
    }


class SecurityScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Threat & Integrity Inspector")
        self.root.geometry("640x580")
        self.root.resizable(False, False)
        self.root.configure(bg="#1e1e2e")

        title_lbl = tk.Label(
            root, text="File Threat & Integrity Inspector",
            font=("Segoe UI", 16, "bold"), fg="#cdd6f4", bg="#1e1e2e"
        )
        title_lbl.pack(pady=15)

        file_frame = tk.Frame(root, bg="#1e1e2e")
        file_frame.pack(fill="x", padx=30, pady=5)

        self.path_entry = tk.Entry(
            file_frame, font=("Segoe UI", 10), bg="#313244", fg="#cdd6f4",
            insertbackground="#cdd6f4", relief="flat", width=42
        )
        self.path_entry.pack(side="left", ipady=6, padx=(0, 10))

        upload_btn = tk.Button(
            file_frame, text="Browse File", font=("Segoe UI", 9, "bold"),
            bg="#89b4fa", fg="#11111b", activebackground="#b4befe",
            relief="flat", cursor="hand2", padx=14, pady=4, command=self.select_file
        )
        upload_btn.pack(side="left")

        scan_btn = tk.Button(
            root, text="Scan & Inspect", font=("Segoe UI", 11, "bold"),
            bg="#a6e3a1", fg="#11111b", activebackground="#94e2d5",
            relief="flat", cursor="hand2", width=25, pady=6, command=self.run_scan
        )
        scan_btn.pack(pady=15)

        self.status_label = tk.Label(
            root, text="Select a file to begin inspection",
            font=("Segoe UI", 11, "bold"), fg="#fab387", bg="#1e1e2e"
        )
        self.status_label.pack(pady=(0, 10))

        output_frame = tk.Frame(root, bg="#181825")
        output_frame.pack(fill="both", expand=True, padx=30, pady=(0, 20))

        self.output_text = tk.Text(
            output_frame, font=("Consolas", 10), bg="#181825", fg="#a6adc8",
            relief="flat", padx=12, pady=12, wrap="word"
        )
        self.output_text.pack(fill="both", expand=True)

    def select_file(self):
        filepath = filedialog.askopenfilename(
            title="Select File",
            filetypes=[("All Files", "*.*"), ("Text Files", "*.txt"), ("Python Files", "*.py")]
        )
        if filepath:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, filepath)

    def run_scan(self):
        filepath = self.path_entry.get().strip()
        if not filepath:
            messagebox.showwarning("Input Error", "Please select a file first.")
            return

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            messagebox.showerror("Read Error", f"Unable to read file: {e}")
            return

        data = analyze_file_content(content)

        self.output_text.delete("1.0", tk.END)

        if not data:
            self.status_label.config(text="File is empty", fg="#f38ba8")
            self.output_text.insert(tk.END, "The selected file contains 0 bytes.")
            return

        if data["database_match"]:
            self.status_label.config(text="CRITICAL THREAT DETECTED", fg="#f38ba8")
        elif len(data["flags"]) >= 2:
            self.status_label.config(text="HIGH RISK FILE", fg="#f38ba8")
        elif len(data["flags"]) == 1:
            self.status_label.config(text="SUSPICIOUS FILE", fg="#fab387")
        else:
            self.status_label.config(text="FILE IS CLEAN", fg="#a6e3a1")

        report = (
            f"Target Path          : {filepath}\n"
            f"Total Characters     : {data['length']}\n"
            f"Printable Bytes      : {data['printable']}\n"
            f"Non-Printable Bytes  : {data['non_printable']}\n"
            f"Most Frequent Byte   : {data['dominant_char']} (Count: {data['dominant_count']})\n"
            f"File Signature (Hash): {data['signature']}\n"
            f"Prime Signature?     : {data['is_prime']}\n"
            f"--------------------------------------------------\n"
        )

        if data["database_match"]:
            report += f"Database Signature Match: {data['database_match']}\n"

        if data["flags"]:
            report += f"Detected Keywords       : {', '.join(data['flags'])}\n"
        else:
            report += "Detected Keywords       : None\n"

        self.output_text.insert(tk.END, report)


if __name__ == "__main__":
    app_window = tk.Tk()
    app = SecurityScannerApp(app_window)
    app_window.mainloop()
