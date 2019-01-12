# cdb

cdb is a Python 3 wrapper for Windows Debugging Tools debugger cdb.exe. cdb allows for advanced debugger scripting and flexability. many methods implemented within cdb could be manually implemented if the need arises.

Heavily based on the PyCDB code from fishstiqz.

Happy debugging!


Breakpoint and Exception Handlers
=================================

When the cdb class is inherited it provides the subclass with methods for handling breakpoints or exceptions.

Implementing the on_breakpoint() function will allow the subclass to handle breakpoints. Additionally, implementing the on_exception() function in the subclass allows handling of exceptions.

Beyond using the on_breakpoint() function, custom handlers can also be implemented independent of the cdb class by passing a handler to the set_bp() function.

Example:

```python
from cdb import cdb

def myhandler():
    print("Called handler!")

dbg = cdb()
dbg.spawn(['notepad.exe'])
dbg.set_bp('kernel32!CreateFileA', handler=myhandler)
dbg.go()
dbg.quit()
````

The example code above will spawn the notepad.exe process. It then sets a breakpoint on kernel32!CreateFileA Windows API function. In this case the code also implements a very simplistic breakpoint handler function called myhandler. The handler is set within the set_bp() method call.

If you run this demo code, notepad will launch when you click the File menu and select Open, the kernel32!CreateFileA breakpoint will be hit. Upon hitting the breakpoint the myhandler() function is called.


Modules
========

cdb tracks module load and module unload events. Module objects can be accessed via the get_modules() method. Alternatively, modules can be directly accessed via cdb.modules.

```python
from cdb import cdb

dbg = cdb()
dbg.spawn(['notepad.exe'])
modules = dbg.get_modules()
for module in modules:
    if module.status:
        status = "Loaded"
    else:
        status = "Unloaded"

    print("Module: %s %s %016x - %016x [ %s ]" (module.name, module.image_path,
         module.start_address, module.end_address, status))

dbg.quit()
````

The above example, will get the modules tracked by cdb, iterate over the modules and print detailed information regarding those modules including: name, image path, start address, end address, and status (loaded or unloaded).


Registers
=========

Architecture specific registers are tracked and accessible via cdb. All the registers can ge collected by calling the get_registers() method. Additionally, methods have been implemented that allows for specific registers to be requested. 

In addition to reading the values of a register, methods exist to write values to registers. Specifically, the set_reg() method allows for setting the value of a specified register.

```python
from cdb import cdb

dbg = cdb()
dbg.spawn(['notepad.exe'])
registers = dbg.get_registers()
rax = dbg.get_reg('rax')
dbg.set_reg('rsp', 0x0000000000000000)
```

The above example depicts the use of all the register related methods.


Basic Machine Information
=====================

To determine the machine type automatically, use the auto_processor argument to the cdb class. The auto_processor argument is set to True by default. Additionally, there is the get_machinetype() method that returns a tuple of the architecture and bit width of registers in that machine mode. Machine type information is based on the PE headers _IMAGE_HEADER MachineType field contained within the main module.

```python
from cdb import cdb

dbg = cdb()
dbg.spawn(['notepad.exe'])
arch, bits = dbg.get_machinetype()
print("%s - %d bits" % (arch, bits))
````

The above example will use the get_machinetype() method to print out information about the machine mode the processor is in.


Todo
=====

* Add support for writing to memory beyond just executing straight cdb commands?
* Add support for reading memory beyond just executing cdb commands?
* Better documentation ;)
