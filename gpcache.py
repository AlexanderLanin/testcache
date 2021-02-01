#!/usr/bin/env python3
"""GPCache is a general purpose cache for pretty much any cachable tool you run repeatadly. See README for more info."""
import argparse
import hashlib
import os
import os.path
import sys
import yaml
from errno import EPERM
from logging import error

import ptrace
from ptrace import PtraceError
from ptrace.debugger import (NewProcessEvent, ProcessExecution,
                             ProcessExit, ProcessSignal, PtraceDebugger)
from ptrace.debugger.process import PtraceProcess
from ptrace.func_call import FunctionCallOptions
from ptrace.syscall import PtraceSyscall


class Inputs:
    """Holds collection of all inputs which should lead to the same output."""

    command_line: str
    files_to_hash = {}  # path -> hash
    files_to_stat = {}  # fd_or_filename -> stat
    files_to_access = {}  # (pathname, mode) -> result

    # ToDo:
    # - cwd/pwd
    # - some env variables like SOURCE_DATE_EPOCH
    #   (never ending list... but adding everything would be overkill)
    # - uid, gid ?!

    def cache_additional_file(self, filename: str) -> None:
        if filename == "/dev/urandom":
            # bad idea trying to hash that... probably check for regular files?
            error("random number is used!")
        else:
            self.files_to_hash[filename] = Utils.calculate_hash_of_file(
                filename)

    def cache_stat(self, fd_or_filename) -> None:
        try:
            stat_result: os.stat_result = os.stat(fd_or_filename)
        except FileNotFoundError:
            stat_result = None

        self.files_to_stat[fd_or_filename] = stat_result

    def cache_access(self, pathname, mode, result) -> None:
        self.files_to_access[(pathname, mode)] = result

    def print_summary(self) -> None:
        print(f"command_line: {self.command_line}")

        for file, digest in self.files_to_hash.items():
            print(f"hash: {file} = {digest}")

        for fd_or_filename, stat_result in self.files_to_stat.items():
            print(f"stat: {fd_or_filename} = {stat_result}")

        for access_params, access_result in self.files_to_access.items():
            print(f"access: {access_params} = {access_result}")


class Outputs:
    """Holds collection of all outputs which a program has produced."""

    files_to_write = {}  # path -> content
    # ToDo: intermixed stdout and stderr
    stdout: str = ""
    stderr: str = ""

    def write_file(self, filename, content) -> None:
        self.files_to_write[filename] += content

    def write_stdout(self, stdout: str) -> None:
        self.stdout = self.stdout + stdout

    def write_stderr(self, stderr: str) -> None:
        self.stderr += stderr

    def print_summary(self) -> None:
        print(f"stdout: {self.stdout}")
        print(f"stderr: {self.stderr}")

        for file, content in self.files_to_write.items():
            print(f"stat: {file} = {content}")


class Utils:
    @staticmethod
    def read_c_string(process: PtraceProcess, addr) -> str:
        """Read C-String from process memory space at addr and return it."""
        data, truncated = process.readCString(addr, 5000)
        if truncated:
            return None  # fail in an obvious way for now
        return data.decode('ASCII')

    # Surprisingly common use case
    @staticmethod
    def read_filename_from_syscall_parameter(
            syscall: PtraceSyscall, argument_name: str) -> str:
        cstring: str = Utils.read_c_string(
            syscall.process, syscall[argument_name].value)
        filename: str = os.fsdecode(cstring)
        return filename

    @staticmethod
    def calculate_hash_of_str(string):
        if isinstance(string, list):
            string = '_'.join(string)
        if isinstance(string, str):
            string = string.encode('ASCII')

        return hashlib.sha256(string).hexdigest()

    @ staticmethod
    def calculate_hash_of_file(file_path):
        # Reuse stat call? Usually there was a stat call before this.
        if not os.path.exists(file_path):
            return None

        # ToDo: investigate intention. cache directory content?
        if(os.path.isdir(file_path)):
            return "directory"

        h = hashlib.sha256()

        with open(file_path, 'rb') as file:
            while True:
                # Reading is buffered, so we can read smaller chunks.
                chunk = file.read(h.block_size)
                if not chunk:
                    break
                h.update(chunk)

        return h.hexdigest()


class FileBackend:
    """Stores cache in local files"""

    # ToDo: XDG
    # ToDo: configurable
    CACHE_DIR: str = ".cache_dir"

    def store(self, command_line, inputs: Inputs, outputs: Outputs) -> str:
        """Stores data in cache and returns unique cache identifier"""

        path = self._get_directory_name(command_line)

        # this should actually iterate over all inputs, regardless of type and
        # check stats, access etc in exactly the right order
        for file in inputs.files_to_hash:
            path += f"/{Utils.calculate_hash_of_file(file)}"

            # for debugging and reports about why cache misses happened store
            # filenames.
            os.makedirs(path, 0o777, True)
            with open(f"{path}/input.yaml", "w") as input_yaml:
                yaml.safe_dump(file, input_yaml)

        with open(f"{path}/outputs.yaml", "w") as outputs_yaml:
            yaml.safe_dump(outputs.files_to_write, outputs_yaml)
            yaml.safe_dump(outputs.stdout, outputs_yaml)
            yaml.safe_dump(outputs.stderr, outputs_yaml)

        return path

    def retrieve(self, command_line) -> Outputs:
        # Descend directory tree as long as there is exactly one further
        # directory or outputs.yaml
        pass

    def clear(self) -> None:
        pass

    # Does python have a concept of private methods?
    def _get_directory_name(self, command_line):
        command_line_hash = Utils.calculate_hash_of_str(command_line)
        executable_hash = Utils.calculate_hash_of_file(command_line[0])
        directory = f"{self.CACHE_DIR}/{command_line_hash}/{executable_hash}"
        return directory


O_READONLY: int = 0
O_CLOEXEC: int = 0o2000000


class FiledescriptorManager:
    """Tracking and especially debugging file descriptor access requires more than a simple array access."""

    fd_to_file_and_state = {}

    def __init__(self):
        self.fd_to_file_and_state[0] = {
            "filename": 0, "state": "open", "source": ["default"]}
        self.fd_to_file_and_state[1] = {
            "filename": 1, "state": "open", "source": ["default"]}
        self.fd_to_file_and_state[2] = {
            "filename": 2, "state": "open", "source": ["default"]}

    def print_fd(self, fd) -> None:
        print(f"file desciptor {fd}:")
        # ToDo wrap all access and allow readonly array access for
        # FiledescriptorManager?
        file_and_state = self.fd_to_file_and_state[fd]
        print("---------------")
        print(f"filename: {file_and_state['filename']}")
        print(f"state: {file_and_state['state']}")
        for src in file_and_state['source']:
            print(f"action: {src}")
        print("---------------")

    def print_all(self) -> None:
        print("Known file desciptors:")
        for fd, file_and_state in self.fd_to_file_and_state.items():
            print("---------------")
            print(f"{fd}")
            print(f"filename: {file_and_state['filename']}")
            print(f"state: {file_and_state['state']}")
            for src in file_and_state['source']:
                print(f"action: {src}")

    def open(self, fd, file, source) -> None:
        if fd in self.fd_to_file_and_state:
            # move to some sort of history
            pass

        self.fd_to_file_and_state[fd] = {
            "filename": file, "state": "open",
            "source": [f"open via {source}"]}

    def close(self, fd, source) -> None:
        if fd not in self.fd_to_file_and_state:
            self.print_all()
            raise Exception(
                f"closing unknown fd {fd}")

        if self.fd_to_file_and_state[fd]["state"] == "closed":
            self.print_all()
            raise Exception(
                f"closing closed fd {fd}")

        self.fd_to_file_and_state[fd]["state"] = "closed"
        self.fd_to_file_and_state[fd]["source"].append(f"close via {source}")

    def get_filename(self, fd, source) -> None:
        if fd not in self.fd_to_file_and_state:
            self.print_all()
            raise Exception(
                f"retrieving unknown fd {fd}")

        if self.fd_to_file_and_state[fd]["state"] != "open":
            self.print_all()
            raise Exception(
                f"retrieving closed fd {fd} => {self.fd_to_file_and_state[fd]}")

        self.fd_to_file_and_state[fd]["source"].append(
            f"get_filename via {source}")
        return self.fd_to_file_and_state[fd]["filename"]


class SyscallListener:
    # In theory this class could be made ptrace independent.
    # But thats a huge amount of wrappers.
    # And what's even the point? This handles Linux specific syscalls anyway.

    filedescriptors = FiledescriptorManager()
    inputs: Inputs
    outputs: Outputs

    def __init__(self, verbose):
        self.verbose = verbose

        self.inputs = Inputs()
        self.outputs = Outputs()

    # Terrible design. Pass Inputs from outside?!
    def set_command_line(self, command_line):
        self.inputs.command_line = command_line

    # ToDo: put this somewhere more global, compare verbose argument
    def log_verbose(self, line) -> None:
        if self.verbose:
            print(line)

    @ staticmethod
    def ignore_syscall(syscall: PtraceSyscall) -> bool:
        # A whitelist for file open etc would be easier, but first we need to
        # find those interesting functions...
        ignore = {
            "arch_prctl",
            "mprotect",
            "mmap",
            "munmap",
            "brk",
            "sbrk",
            "read",
            "pread64"}
        return syscall.name in ignore

    @ staticmethod
    def syscall_to_str(syscall: PtraceSyscall) -> str:
        return f"{syscall.format():80s} = {syscall.result_text}"

    def display_syscall(self, syscall: PtraceSyscall) -> None:
        self.log_verbose(SyscallListener.syscall_to_str(syscall))

    def on_signal(self, event) -> None:
        # ProcessSignal has “signum” and “name” attributes
        # Note: ProcessSignal has a display() method to display its content.
        #       Use it just after receiving the message because it reads
        #       process memory to analyze the reasons why the signal was sent.
        self.log_verbose(f"ToDo: handle signal {event}")

    def on_process_exited(self, event: ProcessExit) -> None:
        # process exited with an exitcode, killed by a signal or exited
        # abnormally. Note: ProcessExit has “exitcode” and “signum” attributes
        # (both can be None)
        state = event.process.syscall_state
        if (state.next_event == "exit") and state.syscall:
            self.log_verbose("Process was killed by a syscall:")
            self.display_syscall(state.syscall)

        # Display exit message
        self.log_verbose(f"*** {event} ***")

    def on_new_process_event(self, event: NewProcessEvent) -> None:
        # new process created, e.g. after a fork() syscall
        # use process.parent attribute to get the parent process.
        process = event.process
        self.log_verbose("*** New process %s ***" % process.pid)
        # TODO: where is prepareProcess gone?
        # self.prepareProcess(process)

    def on_process_execution(self, event) -> None:
        process = event.process
        self.log_verbose("*** Process %s execution ***" % process.pid)

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
            log_syscall = True

            if syscall.name == "openat":
                flags: int = syscall['flags'].value
                readonly: bool = flags in (O_READONLY, O_CLOEXEC)
                filename = Utils.read_filename_from_syscall_parameter(
                    syscall, 'filename')

                if readonly:
                    self.inputs.cache_additional_file(filename)
                    log_syscall = False
                else:
                    self.log_verbose(
                        f"> Abort: Not readonly access to {filename}")

                openat_fd: int = syscall.result
                self.filedescriptors.open(
                    openat_fd, filename, self.syscall_to_str(syscall))

            if syscall.name == "access":
                filename = Utils.read_filename_from_syscall_parameter(
                    syscall, 'filename')
                mode = syscall['mode']
                result = syscall.result
                self.inputs.cache_access(filename, mode, result)
                log_syscall = False

            if syscall.name == "stat":
                filename = Utils.read_filename_from_syscall_parameter(
                    syscall, 'filename')

                # It's unfortunately to just cache the stat structure here.
                # It has different members (and therefore different size)
                # depending on a myriad of different things.
                # Therefore stats is called redundantly from Python.
                self.inputs.cache_stat(filename)
                log_syscall = False

            if syscall.name == "fstat":
                stat_fd: int = syscall['fd'].value
                self.inputs.cache_stat(
                    self.filedescriptors.get_filename(
                        stat_fd, self.syscall_to_str(syscall)))
                log_syscall = False

            if syscall.name == "close":
                close_fd: int = syscall['fd'].value
                self.filedescriptors.close(
                    close_fd, self.syscall_to_str(syscall))
                log_syscall = False

            if syscall.name in ("write"):
                write_fd: int = syscall['fd'].value
                self.filedescriptors.get_filename(
                    write_fd, self.syscall_to_str(syscall))

                buf: str = Utils.read_c_string(
                    syscall.process, syscall['buf'].value)
                if write_fd == 1:
                    self.outputs.write_stdout(buf)

            if log_syscall:
                self.display_syscall(syscall)


class MyDebuggerWrapper:
    """Main logic class?! Merge with SyscallListener?"""

    def __init__(self, verbose):
        self.verbose = verbose

        self.debugger = PtraceDebugger()
        self.debugger.traceFork()
        self.debugger.traceExec()
        self.debugger.traceClone()
        self.debugger.enableSysgood()

        self.syscall_listener = SyscallListener(verbose)

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


class GPCache():
    """
    This is basically the user interface class.

    It will probably also contain stuff like printing statistics and clearing cache.
    """

    def __init__(self, argv):
        self.args = parse_args(argv)

    @ staticmethod
    def run_and_collect(args):
        debugger = MyDebuggerWrapper(args.verbose)
        debugger.syscall_listener.set_command_line(args.program)

        try:
            debugger.run(args.program)
        except ProcessExit:  # as event:
            # FIXME: where is processExited?
            # processExited(event)
            pass
        except PtraceError as err:
            print(f"ptrace() error: {err}")
        except KeyboardInterrupt:
            print("Interrupted.")

        return (debugger.syscall_listener.inputs,
                debugger.syscall_listener.outputs)

    @ staticmethod
    def return_cached_or_run():
        pass

    def main(self):
        backend = FileBackend()
        # outputs = backend.retrieve(self.args)

        if self.args.program:
            inputs, outputs = GPCache.run_and_collect(self.args)
            print("\n\nEverything to cache:")
            inputs.print_summary()
            print("\n\nCached output:")
            outputs.print_summary()

            location = backend.store(self.args.program, inputs, outputs)
            print(f"cached data stored in {location}")


def parse_args(argv):
    # short options taken over from ccache for familiarity
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "program", nargs='+',
        help="Full command line with parameters which this tool is supposed to cache")
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print lots of logs to stdout (later to file)")
    parser.add_argument(
        "-s",
        "--stats",
        action="store_true",
        help="Print statistics on how much was cached (not yet implemented)")
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Run program and verify cache instead of using cached results (not yet implemented)")
    parser.add_argument(
        "-C",
        "--clear_cache",
        action="store_true",
        help="Remove everything from cache (not yet implemented)")
    parser.add_argument(
        "-z",
        "--clear_stats",
        action="store_true",
        help="Reset all statistics to 0 (not yet implemented)")
    parser.add_argument("--version", action="store_true",
                        help="Print version (not yet implemented)")
    return parser.parse_args(argv)


if __name__ == "__main__":
    GPCache(sys.argv[1:]).main()
