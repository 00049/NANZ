"""
Safe async subprocess wrapper for external security tools.

All subprocess calls are:
- Timeout-bounded (default 30s)
- Logged with scan_id for audit trail
- Wrapped in try/except with safe defaults
- Never run with shell=True to prevent injection
"""

import asyncio
import logging
import shutil
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class SubprocessResult:
    """Result of a safe subprocess execution."""

    stdout: str
    stderr: str
    return_code: int
    timed_out: bool = False
    error: Optional[str] = None


def is_tool_available(tool_name: str) -> bool:
    """Check if a system binary is available on PATH."""
    return shutil.which(tool_name) is not None


async def run_safe_subprocess(
    command: list[str],
    timeout: float = 30.0,
    scan_id: str = "unknown",
    tool_name: str = "unknown",
) -> SubprocessResult:
    """
    Run a subprocess safely with timeout and full audit logging.

    Args:
        command: List of command arguments (NO shell=True).
        timeout: Max seconds to wait for the process.
        scan_id: Scan ID for audit trail logging.
        tool_name: Human-readable name of the tool being run.

    Returns:
        SubprocessResult with stdout, stderr, return_code, and error info.
    """
    logger.info(
        f"[{scan_id}] Running {tool_name}: {' '.join(command[:5])}..."
    )

    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            logger.warning(
                f"[{scan_id}] {tool_name} timed out after {timeout}s"
            )
            return SubprocessResult(
                stdout="",
                stderr="",
                return_code=-1,
                timed_out=True,
                error=f"{tool_name} timed out after {timeout}s",
            )

        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")
        return_code = process.returncode or 0

        if return_code != 0:
            logger.warning(
                f"[{scan_id}] {tool_name} exited with code {return_code}: "
                f"{stderr[:200]}"
            )

        logger.info(
            f"[{scan_id}] {tool_name} completed with code {return_code}, "
            f"stdout={len(stdout)} bytes"
        )

        return SubprocessResult(
            stdout=stdout,
            stderr=stderr,
            return_code=return_code,
        )

    except FileNotFoundError:
        logger.error(f"[{scan_id}] {tool_name} binary not found on PATH")
        return SubprocessResult(
            stdout="",
            stderr="",
            return_code=-1,
            error=f"{tool_name} not installed",
        )
    except PermissionError:
        logger.error(f"[{scan_id}] Permission denied running {tool_name}")
        return SubprocessResult(
            stdout="",
            stderr="",
            return_code=-1,
            error=f"Permission denied for {tool_name}",
        )
    except Exception as e:
        logger.error(
            f"[{scan_id}] {tool_name} failed unexpectedly: {e}",
            exc_info=True,
        )
        return SubprocessResult(
            stdout="",
            stderr="",
            return_code=-1,
            error=str(e),
        )
