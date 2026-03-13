import threading
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn, Progress, SpinnerColumn,
    TaskID, TextColumn, TimeElapsedColumn,
)
from rich.table import Table
from rich import box

console = Console()

BANNER = """[bold red]
 ██████╗ ███████╗███╗  ██╗██████╗  ██████╗ ████████╗
 ██╔══██╗██╔════╝████╗ ██║██╔══██╗██╔═══██╗╚══██╔══╝
 ██████╔╝█████╗  ██╔██╗██║██████╔╝██║   ██║   ██║
 ██╔═══╝ ██╔══╝  ██║╚████║██╔══██╗██║   ██║   ██║
 ██║     ███████╗██║ ╚███║██████╔╝╚██████╔╝   ██║
 ╚═╝     ╚══════╝╚═╝  ╚══╝╚═════╝  ╚═════╝    ╚═╝[/]
[dim]  by Orkun — Automated Pentest Framework[/]
"""

def print_banner():
    console.print(BANNER)

def ask_aggressive(target: str) -> bool:
    console.print()
    console.print(Panel(
        f"[bold yellow]Hedef:[/] [cyan]{target}[/]\n\n"
        "[bold white]AGRESİF MOD[/]\n"
        "  [red]•[/] nuclei fuzzing + brute-force template'leri dahil\n"
        "  [red]•[/] ffuf büyük wordlist kullanır\n"
        "  [red]•[/] Daha fazla istek → IDS tetiklenebilir, loglanır\n\n"
        "[bold white]PASİF MOD[/]\n"
        "  [green]•[/] Sadece misconfig, CVE, exposed panel\n"
        "  [green]•[/] Düşük profil — bug bounty için genellikle yeterli\n\n"
        "[dim]Sadece yetkili olduğun scope'larda kullan.[/]",
        title="[bold red]MOD SEÇİMİ[/]",
        border_style="yellow",
    ))
    console.print()
    while True:
        choice = console.input(
            "[bold]Agresif mod kullanılsın mı?[/] [dim](e/h)[/] [bold yellow]>[/] "
        ).strip().lower()
        if choice in ("e", "evet", "y", "yes"):
            console.print("[bold red]⚡ AGRESİF MOD AKTİF[/]\n")
            return True
        elif choice in ("h", "hayir", "hayır", "n", "no"):
            console.print("[bold green]✓ Pasif mod seçildi[/]\n")
            return False
        console.print("[dim]Lütfen 'e' veya 'h' gir.[/]")


class Dashboard:
    def __init__(self, target: str, mode: str, aggressive: bool):
        self.target     = target
        self.mode       = mode
        self.aggressive = aggressive
        self._lock      = threading.Lock()

        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description:<28}[/]"),
            BarColumn(bar_width=28),
            TextColumn("[bold]{task.percentage:>5.0f}%[/]"),
            TextColumn("[dim]{task.fields[status]}[/]"),
            TimeElapsedColumn(),
            console=console,
        )
        self._tasks: dict[str, TaskID] = {}

    def add_task(self, name: str, description: str):
        tid = self.progress.add_task(description, total=100, status="bekliyor")
        self._tasks[name] = tid

    def update(self, name: str, status: str, pct: float):
        if name not in self._tasks:
            return
        tid = self._tasks[name]
        status_str = {
            "running": "[yellow]çalışıyor...[/]",
            "done":    "[green]✓ tamamlandı[/]",
            "error":   "[red]✗ hata[/]",
            "skip":    "[dim]atlandı[/]",
        }.get(status, status)
        self.progress.update(tid, completed=int(pct * 100), status=status_str)

    def log(self, msg: str):
        with self._lock:
            console.log(msg)

    def start(self):
        console.print()
        info = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        info.add_column(style="dim")
        info.add_column(style="bold cyan")
        info.add_row("Hedef",   self.target)
        info.add_row("Mod",     self.mode.upper())
        info.add_row("Agresif", "[red]EVET[/]" if self.aggressive else "[green]HAYIR[/]")
        console.print(Panel(info, title="[bold]TARAMA BAŞLIYOR[/]", border_style="cyan"))
        console.print()
        self.progress.start()

    def stop(self):
        self.progress.stop()
        console.print()
        console.print(Panel(
            "[bold green]✓ Tüm fazlar tamamlandı[/]",
            border_style="green",
        ))