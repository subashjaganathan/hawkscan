"""Dynamic (behavioural) analysis: run a sample in isolation and observe it.

DANGER: this module executes the sample. It must only ever be used inside a
disposable, network-controlled virtual machine. By design it refuses to run
unless the operator has explicitly marked the environment as a sandbox.
"""

from .sandbox import run_sample, SandboxResult, is_sandbox_environment, SANDBOX_ENV_FLAG

__all__ = ["run_sample", "SandboxResult", "is_sandbox_environment", "SANDBOX_ENV_FLAG"]
