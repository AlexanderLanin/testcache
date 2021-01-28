#!/usr/bin/env python3
"""magiccache is a magic cache :-) see README."""
import argparse
import hashlib
import os
import os.path
import sys
from errno import EPERM
from logging import error

import ptrace
from ptrace import PtraceError
from ptrace.debugger import (NewProcessEvent, ProcessExecution,
                             ProcessExit, ProcessSignal, PtraceDebugger)
from ptrace.debugger.process import PtraceProcess
from ptrace.error import PTRACE_ERRORS
from ptrace.func_call import FunctionCallOptions
from ptrace.syscall import PtraceSyscall

# ToDo: tcache and testcache are already reserved on GitHub.
#       bincache/bcache? genericcache?
# How about slowtestcache? magiccache?


class Inputs:
    """Holds collection of all inputs which should lead to the same output."""

    files_to_hash = {}  # path -> hash
    files_to_stat = {}  # path -> stat

    def cache_additional_file(self, filename: str) -> None:
        self.files_to_hash[filename] = Utils.get_digest(filename)

    def cache_stat(self, filename: str) -> None:
        try:
            stat_result: os.stat_result = os.stat(filename)
        except FileNotFoundError:
            stat_result = None

        self.files_to_stat[filename] = stat_result

    def print_summary(self) -> None:
        for file, digest in self.files_to_hash.items():
            print(f"hash: {file} = {digest}")

        for file, stat_result in self.files_to_stat.items():
            print(f"stat: {file} = {stat_result}")


class Utils:
    @staticmethod
    def read_c_string(process: PtraceProcess, addr) -> str:
        """Read C-String from process memory space at addr and return it."""
        data, truncated = process.readCString(addr, 5000)
        if truncated:
            return None  # fail in an obvious way for now
        return data

    # Surprisingly common use case
    @staticmethod
    def read_filename_from_syscall_parameter(
            syscall: PtraceSyscall, argument_name: str) -> str:
        cstring: str = Utils.read_c_string(
            syscall.process, syscall[argument_name].value)
        filename: str = os.fsdecode(cstring)
        return filename

    @staticmethod
    def get_digest(file_path):
        # Reuse stat call? Usually there was a stat call before this.
        if not os.path.exists(file_path):
            return None

        h = hashlib.sha256()

        with open(file_path, 'rb') as file:
            while True:
                # Reading is buffered, so we can read smaller chunks.
                chunk = file.read(h.block_size)
                if not chunk:
                    break
                h.update(chunk)

        return h.hexdigest()


O_READONLY: int = 0
O_CLOEXEC: int = 0o2000000


class SyscallListener:
    # In theory this class could be made ptrace independent.
    # But thats a huge amount of wrappers.
    # And what's even the point? This handles Linux specific syscalls anyway.

    inputs: Inputs

    # stdout, stderr... but mixed... puh...
    output: int

    filedescriptor_to_path = {}

    def __init__(self):
        self.inputs = Inputs()

    @staticmethod
    def ignore_syscall(syscall: PtraceSyscall) -> bool:
        # A whitelist for file open etc would be easier, but first we need to
        # find those interesting functions...
        ignore = {"arch_prctl", "mprotect", "pread64", "pwrite64", "read",
                  "write", "mmap", "munmap", "brk", "sbrk"}
        return syscall.name in ignore

    @staticmethod
    def display_syscall(syscall: PtraceSyscall) -> None:
        print(f"{syscall.format():80s} = {syscall.result_text}")

    def on_signal(self, _event) -> None:
        # ProcessSignal has “signum” and “name” attributes
        # Note: ProcessSignal has a display() method to display its content.
        #       Use it just after receiving the message because it reads
        #       process memory to analyze the reasons why the signal was sent.
        return

    def on_process_exited(self, event: ProcessExit) -> None:
        # process exited with an exitcode, killed by a signal or exited
        # abnormally. Note: ProcessExit has “exitcode” and “signum” attributes
        # (both can be None)
        state = event.process.syscall_state
        if (state.next_event == "exit") and state.syscall:
            # Process was killed by a syscall
            SyscallListener.display_syscall(state.syscall)

        # Display exit message
        error(f"*** {event} ***")

    def on_new_process_event(self, event: NewProcessEvent) -> None:
        # new process created, e.g. after a fork() syscall
        # use process.parent attribute to get the parent process.
        process = event.process
        error("*** New process %s ***" % process.pid)
        # TODO: where is prepareProcess gone?
        # self.prepareProcess(process)

    def on_process_execution(self, event) -> None:
        process = event.process
        error("*** Process %s execution ***" % process.pid)

    def on_syscall(self, process: PtraceProcess):
        state = process.syscall_state
        syscall: PtraceSyscall = state.event(FunctionCallOptions(
            write_types=True,
            write_argname=True,
            string_max_length=200,
            replace_socketcall=False,
            write_address=True,
            max_array_count=50,
        ))
        if syscall and syscall.result is not None \
                and not SyscallListener.ignore_syscall(syscall):
            SyscallListener.display_syscall(syscall)

            if syscall.name == "openat":
                flags: int = syscall['flags'].value
                readonly: bool = flags == O_READONLY or flags == O_CLOEXEC
                filename = Utils.read_filename_from_syscall_parameter(
                    syscall, 'filename')
                if readonly:
                    self.inputs.cache_additional_file(filename)
                else:
                    print(f"> Abort: Not readonly access to {filename}")

                openat_fd: int = syscall.result
                self.filedescriptor_to_path[openat_fd] = filename

            if syscall.name == "access":
                filename = Utils.read_filename_from_syscall_parameter(
                    syscall, 'filename')
                # ToDo: for now just cache the entire file
                print(f"> cache file access rights: {filename}")
                self.inputs.cache_additional_file(filename)

            if syscall.name == "stat":
                filename = Utils.read_filename_from_syscall_parameter(
                    syscall, 'filename')

                # It's unfortunately to just cache the stat structure here.
                # It has different members (and therefore different size)
                # depending on a myriad of different things.
                # Therefore stats is called redundantly from Python.
                self.inputs.cache_stat(filename)

            if syscall.name == "fstat":
                stat_fd: int = syscall['fd'].value
                self.inputs.cache_stat(self.filedescriptor_to_path[stat_fd])

            if syscall.name == "close":
                close_fd: int = syscall['fd'].value
                del self.filedescriptor_to_path[close_fd]


class MyDebuggerWrapper:
    """Main logic class?! Merge with SyscallListener?"""

    def __init__(self):
        self.debugger = PtraceDebugger()
        self.debugger.traceFork()
        self.debugger.traceExec()
        self.debugger.traceClone()
        self.debugger.enableSysgood()

        self.syscall_listener = SyscallListener()

    def __del__(self):
        self.debugger.quit()

    def run(self, program):
        """Debug process and trigger syscall_listener on every syscall."""
        # Create stopped process (via fork followed by PTRACE_TRACEME) with
        # given parameters
        try:
            pid: int = ptrace.debugger.child.createChild(program,
                                                         False,  # print stdout/stderr
                                                         None)  # copy Env

            process: PtraceProcess = self.debugger.addProcess(
                pid, is_attached=True)
        except (ProcessExit, PtraceError) as err:
            if isinstance(err, PtraceError) and err.errno == EPERM:
                error("ERROR: You are not allowed to trace child process!")
            else:
                error("ERROR: Process can no be attached!")
            return

        # Start process, but break at system calls
        process.syscall()

        # Turn exception based interface into one that uses on_* methods.
        # ToDo: what exactly does this condition test?
        while self.debugger:
            try:
                # We have set breakpoints to occure on syscalls.
                # Therefore breakpoint are handled by onSyscall.
                break_point = self.debugger.waitSyscall()
                self.syscall_listener.on_syscall(break_point.process)
                # Docs: proceed with syscall??
                # Reality??: break at next one
                break_point.process.syscall()
            except ProcessExit as interrupt:
                self.syscall_listener.on_process_exited(interrupt)
            except ProcessSignal as signal:
                self.syscall_listener.on_signal(signal)
                signal.process.syscall(signal.signum)
            except NewProcessEvent as event:
                self.syscall_listener.on_new_process_event(event)
                event.process.parent.syscall()
            except ProcessExecution as process_exec:
                self.syscall_listener.on_process_execution(process_exec)
                process_exec.process.syscall()


class TCache():
    """
    This is basically the user interface class.

    It will probably also contain stuff like printing statistics and clearing cache.
    """

    def __init__(self, args):
        self.args = args

    @staticmethod
    def run_and_collect_inputs(args) -> Inputs:
        debugger = MyDebuggerWrapper()
        try:
            # "must be a tuple or list" ??
            debugger.run([args.program])
        except ProcessExit:  # as event:
            # FIXME: where is processExited?
            # processExited(event)
            pass
        except PtraceError as err:
            print(f"ptrace() error: {err}")
        except KeyboardInterrupt:
            print("Interrupted.")
        except PTRACE_ERRORS as err:  # noqa: W0703
            print(f"Debugger error {err}")

        print("\n\nEverything to cache:")
        return debugger.syscall_listener.inputs

    @staticmethod
    def return_cached_or_run():
        pass

    def main(self):
        if self.args.program:
            inputs = TCache.run_and_collect_inputs(self.args)
            inputs.print_summary()


def parse_args(argv):
    # short options taken over from ccache for familiarity
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "program",
        help="Full command line with parameters which this tool is supposed to cache")
    parser.add_argument(
        "-v",
        "-verbose",
        action="store_true",
        help="Print lots of logs to stdout (not yet implemented)")
    parser.add_argument(
        "-s",
        "-stats",
        action="store_true",
        help="Print statistics on how much was cached (not yet implemented)")
    parser.add_argument(
        "-verify",
        action="store_true",
        help="Run program and verify cache instead of using cached results (not yet implemented)")
    parser.add_argument(
        "-C",
        "-clear_cache",
        action="store_true",
        help="Remove everything from cache (not yet implemented)")
    parser.add_argument(
        "-z",
        "-clear_stats",
        action="store_true",
        help="Reset all statistics to 0 (not yet implemented)")
    parser.add_argument("--version", action="store_true",
                        help="Print version (not yet implemented)")
    return parser.parse_args(argv)


if __name__ == "__main__":
    args = parse_args(sys.argv[1:])
    TCache(args).main()
