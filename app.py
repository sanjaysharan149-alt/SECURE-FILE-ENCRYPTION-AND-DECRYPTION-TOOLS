#!/usr/bin/env python3
"""Desktop demo for the AES file encryption tool."""

import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import crypto_tool


class SecureFileVaultApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Secure File Vault")
        self.root.geometry("620x430")
        self.root.minsize(560, 390)

        self.input_path = tk.StringVar()
        self.output_path = tk.StringVar()
        self.output_was_chosen = False
        self.password = tk.StringVar()
        self.mode = tk.StringVar(value="encrypt")
        self.status = tk.StringVar(value="Choose a file to begin.")
        self.busy = False

        self._build_interface()
        self.mode.trace_add("write", self._update_default_output)

    def _build_interface(self) -> None:
        main = ttk.Frame(self.root, padding=24)
        main.pack(fill="both", expand=True)
        main.columnconfigure(1, weight=1)

        ttk.Label(main, text="Secure File Vault", font=("Segoe UI", 22, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 4)
        )
        ttk.Label(
            main,
            text="AES-256-GCM file encryption and integrity protection",
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 24))

        ttk.Label(main, text="Operation").grid(row=2, column=0, sticky="w", pady=8)
        operation_frame = ttk.Frame(main)
        operation_frame.grid(row=2, column=1, columnspan=2, sticky="w")
        ttk.Radiobutton(
            operation_frame, text="Encrypt", variable=self.mode, value="encrypt"
        ).pack(side="left", padx=(0, 18))
        ttk.Radiobutton(
            operation_frame, text="Decrypt", variable=self.mode, value="decrypt"
        ).pack(side="left")

        ttk.Label(main, text="Input file").grid(row=3, column=0, sticky="w", pady=8)
        ttk.Entry(main, textvariable=self.input_path).grid(
            row=3, column=1, sticky="ew", padx=(12, 8)
        )
        ttk.Button(main, text="Browse...", command=self._choose_input).grid(row=3, column=2)

        ttk.Label(main, text="Output file").grid(row=4, column=0, sticky="w", pady=8)
        ttk.Entry(main, textvariable=self.output_path).grid(
            row=4, column=1, sticky="ew", padx=(12, 8)
        )
        ttk.Button(main, text="Save as...", command=self._choose_output).grid(row=4, column=2)

        ttk.Label(main, text="Password").grid(row=5, column=0, sticky="w", pady=8)
        ttk.Entry(main, textvariable=self.password, show="*").grid(
            row=5, column=1, columnspan=2, sticky="ew", padx=(12, 0)
        )

        self.action_button = ttk.Button(main, text="Encrypt File", command=self._start_operation)
        self.action_button.grid(row=6, column=0, columnspan=3, sticky="ew", pady=(24, 12))

        self.progress = ttk.Progressbar(main, mode="indeterminate")
        self.progress.grid(row=7, column=0, columnspan=3, sticky="ew", pady=(0, 12))
        ttk.Label(main, textvariable=self.status, wraplength=560).grid(
            row=8, column=0, columnspan=3, sticky="w"
        )

        ttk.Label(
            main,
            text="Your password is used only for this operation and is never stored.",
            foreground="#555555",
        ).grid(row=9, column=0, columnspan=3, sticky="w", pady=(30, 0))

    def _choose_input(self) -> None:
        path = filedialog.askopenfilename(title="Select a file")
        if path:
            self.input_path.set(path)
            self._update_default_output()

    def _choose_output(self) -> None:
        path = filedialog.asksaveasfilename(title="Choose output file")
        if path:
            self.output_path.set(path)
            self.output_was_chosen = True

    def _update_default_output(self, *_args) -> None:
        input_path = self.input_path.get()
        if input_path and not self.output_was_chosen:
            self.output_path.set(crypto_tool.default_output_path(input_path, self.mode.get()))
        self.action_button.configure(
            text="Encrypt File" if self.mode.get() == "encrypt" else "Decrypt File"
        )

    def _start_operation(self) -> None:
        input_path = self.input_path.get().strip()
        output_path = self.output_path.get().strip()
        password = self.password.get()

        if not input_path or not os.path.isfile(input_path):
            messagebox.showerror("Missing input", "Select an existing input file.")
            return
        if not output_path:
            messagebox.showerror("Missing output", "Choose an output file.")
            return
        if os.path.abspath(input_path) == os.path.abspath(output_path):
            messagebox.showerror("Invalid output", "The output file must differ from the input file.")
            return
        if not password:
            messagebox.showerror("Missing password", "Enter a password before continuing.")
            return

        if os.path.exists(output_path) and not messagebox.askyesno(
            "Overwrite file?", "The output file already exists. Replace it?"
        ):
            return

        self.busy = True
        self.password.set("")
        self.action_button.configure(state="disabled")
        self.progress.start(10)
        self.status.set("Working... Please wait.")
        threading.Thread(
            target=self._run_operation,
            args=(input_path, output_path, password, self.mode.get()),
            daemon=True,
        ).start()

    def _run_operation(self, input_path: str, output_path: str, password: str, mode: str) -> None:
        try:
            if mode == "encrypt":
                crypto_tool.encrypt_file(input_path, output_path, password)
                result = "Encryption completed successfully."
            else:
                crypto_tool.decrypt_file(input_path, output_path, password)
                result = "Decryption completed successfully."
            self.root.after(0, self._finish, result, False)
        except (OSError, ValueError, SystemExit) as error:
            self.root.after(0, self._finish, str(error), True)

    def _finish(self, message: str, failed: bool) -> None:
        self.progress.stop()
        self.action_button.configure(state="normal")
        self.busy = False
        self.status.set(message)
        if failed:
            messagebox.showerror("Operation failed", message)
        else:
            messagebox.showinfo("Success", message)


def main() -> None:
    root = tk.Tk()
    SecureFileVaultApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
    