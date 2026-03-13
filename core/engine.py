import subprocess
import shlex
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable


def run_cmd(cmd: str | list, timeout: int = 120, shell: bool = False) -> tuple[int, str, str]:
    """Komutu çalıştır, (returncode, stdout, stderr) döndür."""
    try:
        if isinstance(cmd, str) and not shell:
            cmd = shlex.split(cmd)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=shell,
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"
    except FileNotFoundError as e:
        return -2, "", f"ARAÇ BULUNAMADI: {e}"
    except Exception as e:
        return -3, "", str(e)


def run_parallel(
    tasks: dict[str, Callable],
    progress_callback: Callable[[str, str, float], None] | None = None,
) -> dict:
    """
    tasks = {"görev_adı": callable} sözlüğü alır.
    Her callable sonucu döndürür.
    progress_callback(görev_adı, durum, yüzde) çağrılır.
    """
    results = {}
    total   = len(tasks)
    done    = 0
    lock    = threading.Lock()

    def wrapped(name: str, fn: Callable):
        nonlocal done
        if progress_callback:
            progress_callback(name, "running", 0.0)
        try:
            result = fn()
        except Exception as e:
            result = {"error": str(e)}
        with lock:
            done += 1
            pct = done / total
        if progress_callback:
            progress_callback(name, "done", pct)
        return name, result

    with ThreadPoolExecutor(max_workers=min(total, 6)) as executor:
        futures = {executor.submit(wrapped, name, fn): name for name, fn in tasks.items()}
        for future in as_completed(futures):
            name, result = future.result()
            results[name] = result

    return results


def check_tool(path: str) -> bool:
    """Araç var mı kontrol et."""
    code, _, _ = run_cmd(f"which {path}" if "/" not in path else f"test -f {path}", shell=True)
    return code == 0