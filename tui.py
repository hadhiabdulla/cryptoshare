"""CryptoShare TUI - loopback demo surface for the AI-pipeline secret-sharing track.

Shows the pipeline live: what stays on the device (plaintext, master key, 2 shares),
what the relay stores (ciphertext, wrapped key, 1 share - visible in /inspector),
and where the documented exposure point is (hosted LLM inference).
"""
import subprocess
import sys
import time

from rich.box import ASCII
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import crypto_core as cc
import client as cl

console = Console()
RELAY = "http://127.0.0.1:8787"


def banner():
    console.print(Panel.fit(
        "[bold cyan]CryptoShare[/] - AI pipeline secret sharing demo\n"
        "Encrypt on device -> relay stores only ciphertext -> hosted LLM answers.\n"
        "[dim]Master key never leaves this device whole (Shamir 2-of-3).[/]",
        box=ASCII,
        border_style="cyan"))


def run(question: str):
    banner()
    import os
    K = os.urandom(32)
    shares = cc.split_secret(K, 2, 3)

    t = Table(title="Master key custody (Shamir 2-of-3)", show_lines=False, box=ASCII)
    t.add_column("Share")
    t.add_column("Held by")
    t.add_column("Alone can decrypt?")
    t.add_row("share 1", "[green]this device[/]", "no")
    t.add_row("share 2", "[green]this device[/]", "no")
    t.add_row("share 3", "[yellow]relay server[/]", "no - one share is never enough")
    console.print(t)

    blob_q = cc.encrypt_message(K, question.encode())
    row = cl._post("/store", cl._hexblob(blob_q, "prompt->agent", shares[2]))["id"]
    console.print(Panel(
        f"Stored on relay as row [bold]{row}[/]:\n"
        f"ciphertext (first 48 hex): [magenta]{blob_q['ciphertext'].hex()[:48]}...[/]\n"
        f"wrapped data key:          [magenta]{blob_q['wrapped_key'].hex()[:48]}...[/]\n"
        f"[dim]Inspector: {RELAY}/inspector[/]",
        title="What left this device", border_style="magenta", box=ASCII))

    served = cl._get(f"/fetch?id={row}")
    K_back = cc.combine_shares(shares[:2])
    pt = cc.decrypt_message(K_back, cl._unhexblob(served)).decode()
    console.print(f"[green]Recovered locally from shares 1+2:[/] {pt}")

    console.print(Panel(
        "Plaintext now crosses to the hosted LLM for inference.\n"
        "[yellow]Documented exposure point:[/] the provider sees this prompt while "
        "answering; its logs/retention are outside this design.",
        title="Inference boundary", border_style="yellow", box=ASCII))
    answer = cl.call_llm(pt)
    console.print(Panel(answer, box=ASCII, title="Agent answer (plaintext, this device only)", border_style="green"))

    blob_a = cc.encrypt_message(K, answer.encode())
    row2 = cl._post("/store", cl._hexblob(blob_a, "agent->user", shares[2]))["id"]
    console.print(f"[dim]Answer stored on relay as ciphertext row {row2}. Demo complete.[/]")


if __name__ == "__main__":
    q = " ".join(sys.argv[1:]) or input("Ask the agent: ")
    run(q)
