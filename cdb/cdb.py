###
## cdb.py is a wrapper around the cdb.exe debugger.
## This code is heavily based on pycdb by fishstiqz.
###

# -author:  @bannedit0
#  date:    January 2019

import os
import re
import sys
import queue
import subprocess
import threading

BREAKPOINT_NORMAL       = 1
BREAKPOINT_UNRESOLVED   = 2
BREAKPOINT_HARDWARE     = 3
BREAKPOINT_SYMBOLIC     = 4

EXCEPTION_ACCESS_VIOLATION          = 0xc0000005
EXCEPTION_DATATYPE_MISALIGNMENT     = 0x80000002
EXCEPTION_BREAKPOINT                = 0x80000003
EXCEPTION_SINGLE_STEP               = 0x80000004
EXCEPTION_ARRAY_BOUNDS_EXCEEDED     = 0xc000008c
EXCEPTION_FLT_DENORMAL_OPERAND      = 0xc000008d
EXCEPTION_FLT_DIVIDE_BY_ZERO        = 0xc000008e
EXCEPTION_FLT_INEXACT_RESULT        = 0xc000008f
EXCEPTION_FLT_INVALID_OPERATION     = 0xc0000090
EXCEPTION_FLT_OVERFLOW              = 0xc0000091
EXCEPTION_FLT_STACK_CHECK           = 0xc0000092
EXCEPTION_FLT_UNDERFLOW             = 0xc0000093
EXCEPTION_INT_DIVIDE_BY_ZERO        = 0xc0000094
EXCEPTION_INT_OVERFLOW              = 0xc0000095
EXCEPTION_PRIV_INSTRUCTION          = 0xc0000096
EXCEPTION_IN_PAGE_ERROR             = 0xc0000006
EXCEPTION_ILLEGAL_INSTRUCTION       = 0xc000001d
EXCEPTION_NONCONTINUABLE_EXCEPTION  = 0xc0000025
EXCEPTION_STACK_OVERFLOW            = 0xc00000fd
EXCEPTION_INVALID_DISPOSITION       = 0xc0000026
EXCEPTION_GUARD_PAGE                = 0x80000001
EXCEPTION_INVALID_HANDLE            = 0xc0000008

# helper function to take addresses from cdb and convert to int
def parse_address(address):
    if isinstance(address, str):
        if address.startswith('??'):
            return 0
        else:
            return int(address.replace('`', ''), 16)
    else:
        return 0

class ExceptionEvent():
    def __init__(self, pid, tid, description, code):
        self.pid = pid
        self.tid = tid
        self.description = description
        self.exception_code = code

    def __str__(self):
        return "ExceptionEvent: <%x:%x> %08x - %s" (pid, tid, code, description)

class BreakpointEvent():
    def __init__(self, num):
        self.num = num

    def __str__(self):
        return "Breakpoint %d hit" % self.num

class Module():
    def __init__(self, name, image_path, start_address, end_address):
        self.name = name
        self.image_path = image_path
        self.start_address = parse_address(start_address)
        self.end_address = parse_address(end_address)
        self.loaded = True

    def __str__(self):
        if self.start_address.bit_length() > 32:
            return "Loaded Module %s %s\t%016x - %016x" % (self.name, self.image_path, 
                    self.start_address, self.end_address)
        else:
            return "Loaded Module %s %s\t%08x - %08x" % (self.name, self.image_path, 
                    self.start_address, self.end_address)

class LoadModule():
    def __init__(self, module):
        self.module = module

    def __str__(self):
        if self.module.start_address.bit_length() > 32:
            return "Loaded Module %s %s\t%016x - %016x" % (self.module.name, 
                    self.module.image_path, self.module.start_address, self.module.end_address)
        else:
            return "Loaded Module %s %s\t%08x - %08x" % (self.module.name, self.module.image_path, 
                    self.module.start_address, self.module.end_address)

class UnloadModule():
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return "Unloaded Module %s" % self.name

class PipeClosed(BaseException):
    pass

class QueueFull(BaseException):
    pass

class Output():
    def __init__(self, output):
        self.output = output

    def __str__(self):
        return "Output: %s" % (self.output)

class Reader(threading.Thread):
    def __init__(self, pipe):
        threading.Thread.__init__(self)
        self.pipe = pipe
        self.queue = queue.Queue()
        self.stop_reading = False

    def run(self):
        line = ''
        while not self.stop_reading:
            c = self.pipe.stdout.read(1)

            if not c:
                self.queue.put(PipeClosed())
                break

            line += c
            self.queue.put(Output(c))
            if self.queue.full():
                raise QueueFull

            if c == '\n':
                self.process_line(line)
                line = ''

    def process_line(self, line):
        if line.startswith('ModLoad: '):
            mod = line.split()
            start_address = mod[1]
            end_address = mod[2]
            image_path = mod[3]
            name = image_path.split('\\')[-1]
            mod = Module(name, image_path, start_address, end_address)
            self.queue.put(LoadModule(mod))

        if line.startswith('Unload module'):
            mod = line.split()[2]
            self.queue.put(UnloadModule(mod))

        if line.startswith('Breakpoint'):
            m = re.match(r'Breakpoint\s(\d)\shit', line)
            num = int(m.group(1))
            self.queue.put(BreakpointEvent(num))

        if line.startswith('Last event'):
            event = line.split(': ')
            pid, tid = event[1].split('.')
            description = event[2]

            # need to check if this is always printed in hex
            code = int(event[2].split('code ').split('(')[0], 16)
            self.queue.put(ExceptionEvent(pid, tid, description, code))

class cdb():
    def __init__(self, cdb_path=None, debug_children=False, auto_processor=True):
        self.pipe = None
        self.debuggable = False
        self.debug_children = False
        self.attached = False
        self.finished = False
        self.cmdline = None
        self.processor_mode = None
        self.bits = 32
        self.modules = []
        self.breakpoints = []
        self.exceptions = []
        self.registers = {}
        self.auto_processor = auto_processor
        self._cdb_path = cdb_path
        self._thread = None
        self._registers = ''
        self._process_mode = None
        self._initial_break = True

        if not self._cdb_path:
            self._cdb_path = self._find_cdb_path()

    def _run(self):
        self.pipe = subprocess.Popen(self.cmdline, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, 
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP, encoding='utf-8', shell=False)
        self._thread = Reader(self.pipe)
        self._thread.start()

        if not self.pipe:
            self.debuggable = False
            self.finished = True
            raise PipeClosed("PipeClosed")

        # enable module unload messages so we can track the state of modules
        self.execute('sxn ud')

        if self.auto_processor:
            self.get_machinetype()

    def wait(self):
        return self.read_to_prompt()

    def write_pipe(self, cmd):
        # ensure we are in a debuggable state
        if not self.debuggable:
            self.read_to_prompt()

        if cmd == 'g':
            self.debuggable = False

        self.pipe.stdin.write('%s\r\n' % cmd)
        self.pipe.stdin.flush()

        if self.finished:
            self.debuggable = False
            raise PipeClosed('Debugging session has already ended')

    def execute(self, cmd, keep_output=True, exclude_prompt=True):
        self.write_pipe(cmd)
        output = self.read_to_prompt(keep_output=keep_output)

        if exclude_prompt:
            # split the output by line, remove the last line (the one containing the prompt)
            output = '\n'.join(output.split('\n')[:-1])
        return output

    def spawn(self, arguments):
        self.cmdline = self.build_cmdline(arguments)
        self._run()

    def attach(self, pid, arguments=[]):
        self.attached = True
        self.cmdline = self.build_cmdline(['-p', str(pid)] + arguments)
        self._run()

    def go(self, timeout=None):
        self.write_pipe('g')
        self.read_to_prompt(timeout=Timeout)
        self.initial_break = False

        # before we return control to the user we need to check if there was an exception
        # that needs to be kept track of
        self.debuggable = True
        self._get_registers()
        self.execute('.lastevent')

    def quit(self):
        self._thread.stop_reading = True
        self.finished = True

        try:
            if self.attached:
                self.write_pipe('qd')
            else:
                self.write_pipe('q')
            self.debuggable = False
            self.pipe.pid.kill()
        except:
            pass

    def set_bp(self, location, handler=None, bptype=BREAKPOINT_NORMAL, bpmode='e', condition=None):
        cmd = ""
        if bptype == BREAKPOINT_NORMAL:
            if isinstance(location, str):
                cmd = 'bp %s' % location
            if isinstance(location, int):
                if location.bit_length() > 32:
                    cmd = 'bp %016x' % location
                else:
                    cmd = 'bp %08x' % location

        elif bptype == BREAKPOINT_UNRESOLVED:
            if isinstance(location, str):
                cmd = 'bu %s' % location
            if isinstance(location, int):
                if location.bit_length() > 32:
                    cmd = 'bu %016x' % location
                else:
                    cmd = 'bu %08x' % location

        elif bptype == BREAKPOINT_SYMBOLIC:
            if isinstance(location, str):
                cmd = 'bm %s' % location
            if isinstance(location, int):
                if location.bit_length() > 32:
                    cmd = 'bm %016x' % location
                else:
                    cmd = 'bm %08x' % location

        elif bptype == BREAKPOINT_HARDWARE:
            if isinstance(location, str):
                cmd = 'ba %s 1 %s' % (bpmode, location)
            if isinstance(location, int):
                if location.bit_length() > 32:
                    cmd = 'ba %s 1 %016x' % (bpmode, location)
                else:
                    cmd = 'ba %s 1 %08x' % (bpmode, location)

        if condition:
            cmd += ' ' + condition

        # set the breakpoint
        self.execute(cmd)
        # get the breakpoint number
        output = self.execute('bl')
        bpnum = None
        for line in output.split('\n'):
            bp_list = line.split()
            if isinstance(location, str):
                if location.lower() == bp_list[-1].lower():
                    bpnum = int(bp_list[0])
            if isinstance(location, int):
                address = parse_address(bp_list[2])
                if address == location:
                    bpnum = int(bp_list[0])

        self.breakpoints.append({'num': bpnum, 'location': location, 'handler': handler, 
            'condition': condition, 'enabled': True})

    def get_bp(self):
        return self.breakpoints

    def disable_bp(self, num):
        if len(self.breakpoints) - 1 >= num:
            self.execute('bd %d' % num)

    def enable_bp(self, num):
        if len(self.breakpoints) - 1 >= num:
            self.execute('be %d' % num)

    def remove_bp(self, num):
        if len(self.breakpoints) - 1 >= num:
            self.breakpoints.pop(num)
            self.execute('bc %d' % num)

    def get_reg(self, name):
        if name in self.registers.keys():
            return self.registers[name]

    def set_reg(self, name, value):
        if name in self.registers.keys():
            if isinstance(value, int):
                self.execute('r @%s = %s' % (name, value))
                self.registers[name] = value

    def search(self, value, mode="d", begin=0, end=0xFFFFFFFF):
        if self.process_mode == 'X64' and end == 0xFFFFFFFF:
            end = 0xFFFFFFFFFFFFFFFF

        if mode == "d" or mode == "w":
            return self.execute("s -%s %x L?%x %x" % (mode, begin, end, value))

        elif mode == "a" or mode == "b":
            return self.execute("s -%s %x L?%x %s" % (mode, begin, end, value))

    def search_int(self, value, begin=0, end=0xFFFFFFFF):
        return self.search(value, "d", begin, end)

    def search_ascii(self, value, begin=0, end=0xFFFFFFFF):
        return self.search(value, "a", begin, end)

    def search_bytes(self, value, begin=0, end=0xFFFFFFFF):
        if isinstance(value, basestring):
            return self.search(value, "b", begin, end)

    def read_to_prompt(self, keep_output=True, timeout=None):
        last = None
        buf = ''

        while True:
            if self.finished:
                raise PipeClosed("Debugging session has already finished")
            try:
                event = self._thread.queue.get(True)
            except queue.Empty:
                break

            if isinstance(event, Output):
                c = event.output
                buf += c

                if last == '>' and c == ' ' and self._thread.queue.empty():
                    # this regex will match a prompt for example:
                    # 0:007>
                    # 0:023:x86> <-- this prompt indicates the processor mode
                    # processor mode can be set to x86 when debugging a 32bit process on a 64bit machine
                    if re.search(r"[0-9]+:[0-9]*.*>", buf, re.MULTILINE):
                        self.debuggable = True
                        if self._initial_break:
                            self._initial_break = False
                            if not self.processor_mode and self.auto_processor:
                                self.get_machinetype()

                            self._registers = self.execute('r')
                            self._parse_registers()
                        break
                last = c

            if isinstance(event, LoadModule):
                self.modules.append(event.module)

            if isinstance(event, UnloadModule):
                for mod in self.modules:
                    if mod.name == event.name:
                        mod.loaded = False

            if isinstance(event, PipeClosed):
                self.debuggable = False
                self.finished = True
                raise PipeClosed(buf)

            if isinstance(event, BreakpointEvent):
                self.debuggable = True
                breakpoint = self.breakpoints[event.num]
                self.process_breakpoint(breakpoint)

            if isinstance(event, ExceptionEvent):
                self.debuggable = True
                self.process_exception(event)

        if keep_output:
            return buf
        else:
            return ''

    def process_breakpoint(self, breakpoint):
        if breakpoint['handler']:
            if callable(breakpoint['handler']):
                breakpoint['handler']()
        else:
            self.on_breakpoint()

    def process_exception(self, exception):
        self.exceptions.append(exception)
        self.on_exception(exception)

    # intended to be overwritten by inheriting class
    def on_breakpoint(self):
        pass

    # intended to be overwritten by inheriting class
    def on_exception(self):
        pass

    def get_modules(self):
        return self.modules

    def get_registers(self):
        return self.registers

    def _get_registers(self):
        self._registers = self.execute('r')
        self._parse_registers()

    def _parse_registers(self):
        # [:-2] cuts the last two lines which includes the current location and instruction
        for line in self._registers.split('\n')[:-2]:
            line = re.sub(' +', ' ', line) # ensure there are no extra spaces
            for reg in line.split(' '):
                if '=' in reg:
                    name, value = reg.split('=')
                    self.registers[name] = int(value, 16)
                else:
                    # default for TF flag
                    self.registers['tf'] = 0

                    # OF flag
                    if reg == 'nv':
                        self.registers['of'] = 0
                    elif reg == 'ov':
                        self.registers['of'] = 1

                    # DF flag
                    elif reg == 'dn':
                        self.registers['df'] = 1
                    elif reg == 'up':
                        self.registers['df'] = 0

                    # CF flag
                    elif reg == 'cy':
                        self.registers['cf'] = 1
                    elif reg == 'nc':
                        self.registers['cf'] = 0

                    # IF flag
                    elif reg == 'ei':
                        self.registers['if'] = 1
                    elif reg == 'di':
                        self.registers['if'] = 0

                    # SF flag
                    elif reg == 'ng':
                        self.registers['sf'] = 1
                    elif reg == 'pl':
                        self.registers['sf'] = 0

                    # ZF flag
                    elif reg == 'zr':
                        self.registers['zf'] = 1
                    elif reg == 'nz':
                        self.registers['zf'] = 0

                    # AF flag
                    elif reg == 'ac':
                        self.registers['af'] = 1
                    elif reg == 'na':
                        self.registers['af'] = 0

                    # PF flag
                    elif reg == 'pe':
                        self.registers['pf'] = 1
                    elif reg == 'po':
                        self.registers['pf'] = 0

                    # TF flag
                    elif reg == 'tf':
                        self.registers['tf'] = 1

    def get_machinetype(self):
        # determine the image of the application and set the processor mode if appropriate
        # this command lists the main module name for use later
        output = self.execute('lm 1ma $exentry')
        output = self.execute('!lmi %s' % output.rstrip())
        for line in output.splitlines():
            if 'Machine Type:' in line:
                m = re.match(r'\s*\w*\s\w*:\s[0-9]*\s\((\w*)\)', line)
                mtype = m.group(1)
                if mtype == 'X64':
                    mtype = 'amd64'
                    self.bits = 64
                elif mtype == 'IA64':
                    mtype = 'ia64'
                    self.bits = 64
                elif mtype == 'I386':
                    mtype = 'x86'
                    self.bits = 32
        if mtype:
            self.processor_mode = mtype
            self.execute('.effmach %s' % mtype)

        return (self.processor_mode, self.bits)

    def build_cmdline(self, arguments):
        cmdline = [self._cdb_path]

        if self.debug_children:
            cmdline.append('-o')

        if arguments and isinstance(arguments, list):
            cmdline += arguments

        return cmdline

    def _find_cdb_path(self):
        programfiles = [ os.environ["PROGRAMFILES"] ]
        if "ProgramW6432" in os.environ:
            programfiles.append(os.environ["ProgramW6432"])
        if "ProgramFiles(x86)" in os.environ:
            programfiles.append(os.environ["ProgramFiles(x86)"])

        # potential paths to the debugger in program files
        dbg_paths = [
            os.path.join('Windows Kits', '10', 'Debuggers', 'x64'),
            os.path.join('Windows Kits', '10', 'Debuggers', 'x86'),
            os.path.join('Windows Kits', '8.1', 'Debuggers', 'x64'),
            os.path.join('Windows Kits', '8.1', 'Debuggers', 'x86'),
            os.path.join('Windows Kits', '8.0', 'Debuggers', 'x64'),
            os.path.join('Windows Kits', '8.0', 'Debuggers', 'x64'),
            "Debugging Tools for Windows (x64)",
            "Debugging Tools for Windows (x86)",
            "Debugging Tools for Windows",
        ]

        # search the paths
        for path in programfiles:
            for d in dbg_paths:
                cdb_path = os.path.join(path, d, 'cdb.exe')
                if os.path.exists(cdb_path):
                    return cdb_path