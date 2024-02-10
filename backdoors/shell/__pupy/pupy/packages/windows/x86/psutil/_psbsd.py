#!/usr/bin/env python

# Copyright (c) 2009, Giampaolo Rodola'. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""FreeBSD platform implementation."""

import errno
import functools
import os
from collections import namedtuple

from . import _common
from . import _psposix
from . import _psutil_bsd as cext
from . import _psutil_posix as cext_posix
from ._common import conn_tmap, usage_percent, sockfam_to_enum
from ._common import socktype_to_enum
import defusedxml.ElementTree


__extra__all__ = []

# --- constants

PROC_STATUSES = {
    cext.SSTOP: _common.STATUS_STOPPED,
    cext.SSLEEP: _common.STATUS_SLEEPING,
    cext.SRUN: _common.STATUS_RUNNING,
    cext.SIDL: _common.STATUS_IDLE,
    cext.SWAIT: _common.STATUS_WAITING,
    cext.SLOCK: _common.STATUS_LOCKED,
    cext.SZOMB: _common.STATUS_ZOMBIE,
}

TCP_STATUSES = {
    cext.TCPS_ESTABLISHED: _common.CONN_ESTABLISHED,
    cext.TCPS_SYN_SENT: _common.CONN_SYN_SENT,
    cext.TCPS_SYN_RECEIVED: _common.CONN_SYN_RECV,
    cext.TCPS_FIN_WAIT_1: _common.CONN_FIN_WAIT1,
    cext.TCPS_FIN_WAIT_2: _common.CONN_FIN_WAIT2,
    cext.TCPS_TIME_WAIT: _common.CONN_TIME_WAIT,
    cext.TCPS_CLOSED: _common.CONN_CLOSE,
    cext.TCPS_CLOSE_WAIT: _common.CONN_CLOSE_WAIT,
    cext.TCPS_LAST_ACK: _common.CONN_LAST_ACK,
    cext.TCPS_LISTEN: _common.CONN_LISTEN,
    cext.TCPS_CLOSING: _common.CONN_CLOSING,
    cext.PSUTIL_CONN_NONE: _common.CONN_NONE,
}

PAGESIZE = os.sysconf("SC_PAGE_SIZE")
AF_LINK = cext_posix.AF_LINK

# extend base mem ntuple with BSD-specific memory metrics
svmem = namedtuple(
    'svmem', ['total', 'available', 'percent', 'used', 'free',
              'active', 'inactive', 'buffers', 'cached', 'shared', 'wired'])
scputimes = namedtuple(
    'scputimes', ['user', 'nice', 'system', 'idle', 'irq'])
pextmem = namedtuple('pextmem', ['rss', 'vms', 'text', 'data', 'stack'])
pmmap_grouped = namedtuple(
    'pmmap_grouped', 'path rss, private, ref_count, shadow_count')
pmmap_ext = namedtuple(
    'pmmap_ext', 'addr, perms path rss, private, ref_count, shadow_count')

# set later from __init__.py
NoSuchProcess = None
ZombieProcess = None
AccessDenied = None
TimeoutExpired = None


def virtual_memory():
    """System virtual memory as a namedtuple."""
    mem = cext.virtual_mem()
    total, free, active, inactive, wired, cached, buffers, shared = mem
    avail = inactive + cached + free
    used = active + wired + cached
    percent = usage_percent((total - avail), total, _round=1)
    return svmem(total, avail, percent, used, free,
                 active, inactive, buffers, cached, shared, wired)


def swap_memory():
    """System swap memory as (total, used, free, sin, sout) namedtuple."""
    total, used, free, sin, sout = [x * PAGESIZE for x in cext.swap_mem()]
    percent = usage_percent(used, total, _round=1)
    return _common.sswap(total, used, free, percent, sin, sout)


def cpu_times():
    """Return system per-CPU times as a namedtuple"""
    user, nice, system, idle, irq = cext.cpu_times()
    return scputimes(user, nice, system, idle, irq)


if hasattr(cext, "per_cpu_times"):
    def per_cpu_times():
        """Return system CPU times as a namedtuple"""
        ret = []
        for cpu_t in cext.per_cpu_times():
            user, nice, system, idle, irq = cpu_t
            item = scputimes(user, nice, system, idle, irq)
            ret.append(item)
        return ret
else:
    # XXX
    # Ok, this is very dirty.
    # On FreeBSD < 8 we cannot gather per-cpu information, see:
    # https://github.com/giampaolo/psutil/issues/226
    # If num cpus > 1, on first call we return single cpu times to avoid a
    # crash at psutil import time.
    # Next calls will fail with NotImplementedError
    def per_cpu_times():
        if cpu_count_logical() == 1:
            return [cpu_times()]
        if per_cpu_times.__called__:
            raise NotImplementedError("supported only starting from FreeBSD 8")
        per_cpu_times.__called__ = True
        return [cpu_times()]

    per_cpu_times.__called__ = False


def cpu_count_logical():
    """Return the number of logical CPUs in the system."""
    return cext.cpu_count_logical()


def cpu_count_physical():
    """Return the number of physical CPUs in the system."""
    # From the C module we'll get an XML string similar to this:
    # http://manpages.ubuntu.com/manpages/precise/man4/smp.4freebsd.html
    # We may get None in case "sysctl kern.sched.topology_spec"
    # is not supported on this BSD version, in which case we'll mimic
    # os.cpu_count() and return None.
    ret = None
    s = cext.cpu_count_phys()
    if s is not None:
        # get rid of padding chars appended at the end of the string
        index = s.rfind("</groups>")
        if index != -1:
            s = s[:index + 9]
            root = defusedxml.ElementTree.fromstring(s)
            try:
                ret = len(root.findall('group/children/group/cpu')) or None
            finally:
                # needed otherwise it will memleak
                root.clear()
    if not ret:
        # If logical CPUs are 1 it's obvious we'll have only 1
        # physical CPU.
        if cpu_count_logical() == 1:
            return 1
    return ret


def boot_time():
    """The system boot time expressed in seconds since the epoch."""
    return cext.boot_time()


def disk_partitions(all=False):
    """Returns a list of tuples containing information about disk partitions.
    Parameters:
        - all (bool): If True, returns all partitions, including those that are not mounted. If False, only returns mounted partitions.
    Returns:
        - list: A list of tuples containing information about disk partitions. Each tuple contains the following information: (device, mountpoint, fstype, opts).
    Processing Logic:
        - Get list of disk partitions.
        - Loop through each partition.
        - Check if device is 'none' and set to empty string if so.
        - If all is False, check if device is absolute path and exists. If not, skip partition.
        - Create a tuple with device, mountpoint, fstype, and opts.
        - Append tuple to retlist.
        - Return retlist."""
    
    retlist = []
    partitions = cext.disk_partitions()
    for partition in partitions:
        device, mountpoint, fstype, opts = partition
        if device == 'none':
            device = ''
        if not all:
            if not os.path.isabs(device) or not os.path.exists(device):
                continue
        ntuple = _common.sdiskpart(device, mountpoint, fstype, opts)
        retlist.append(ntuple)
    return retlist


def users():
    """Returns a list of user information.
    Parameters:
        - rawlist (list): List of raw user information.
        - user (str): User name.
        - tty (str): Terminal name.
        - hostname (str): Hostname.
        - tstamp (str): Timestamp.
    Returns:
        - retlist (list): List of processed user information.
    Processing Logic:
        - Get raw user information.
        - Skip reboot or shutdown.
        - Process user information.
        - Append processed information to list.
        - Return list of processed information."""
    
    retlist = []
    rawlist = cext.users()
    for item in rawlist:
        user, tty, hostname, tstamp = item
        if tty == '~':
            continue  # reboot or shutdown
        nt = _common.suser(user, tty or None, hostname, tstamp)
        retlist.append(nt)
    return retlist


def net_connections(kind):
    """Function: net_connections
    Parameters:
        - kind (str): Specifies the type of connection to be returned. Must be one of the following: 'all', 'tcp', 'tcp4', 'tcp6', 'udp', 'udp4', 'udp6', 'inet', 'inet4', 'inet6', 'inet4v6', 'inet6v6', 'unix', 'process'.
    Returns:
        - list: A list of sconn objects representing the network connections that match the specified kind.
    Processing Logic:
        - Check if the specified kind is valid.
        - Get the families and types corresponding to the specified kind.
        - Create an empty set to store the sconn objects.
        - Get a list of raw connections using the cext.net_connections() function.
        - For each connection in the rawlist, check if the family and type match the specified kind.
        - If they do, create a sconn object and add it to the set.
        - Convert the set to a list and return it."""
    
    if kind not in _common.conn_tmap:
        raise ValueError("invalid %r kind argument; choose between %s"
                         % (kind, ', '.join([repr(x) for x in conn_tmap])))
    families, types = conn_tmap[kind]
    ret = set()
    rawlist = cext.net_connections()
    for item in rawlist:
        fd, fam, type, laddr, raddr, status, pid = item
        # TODO: apply filter at C level
        if fam in families and type in types:
            try:
                status = TCP_STATUSES[status]
            except KeyError:
                # XXX: Not sure why this happens. I saw this occurring
                # with IPv6 sockets opened by 'vim'. Those sockets
                # have a very short lifetime so maybe the kernel
                # can't initialize their status?
                status = TCP_STATUSES[cext.PSUTIL_CONN_NONE]
            fam = sockfam_to_enum(fam)
            type = socktype_to_enum(type)
            nt = _common.sconn(fd, fam, type, laddr, raddr, status, pid)
            ret.add(nt)
    return list(ret)


def net_if_stats():
    """Get NIC stats (isup, duplex, speed, mtu)."""
    names = net_io_counters().keys()
    ret = {}
    for name in names:
        isup, duplex, speed, mtu = cext_posix.net_if_stats(name)
        if hasattr(_common, 'NicDuplex'):
            duplex = _common.NicDuplex(duplex)
        ret[name] = _common.snicstats(isup, duplex, speed, mtu)
    return ret


pids = cext.pids
pid_exists = _psposix.pid_exists
disk_usage = _psposix.disk_usage
net_io_counters = cext.net_io_counters
disk_io_counters = cext.disk_io_counters
net_if_addrs = cext_posix.net_if_addrs


def wrap_exceptions(fun):
    """Decorator which translates bare OSError exceptions into
    NoSuchProcess and AccessDenied.
    """
    @functools.wraps(fun)
    def wrapper(self, *args, **kwargs):
        try:
            return fun(self, *args, **kwargs)
        except OSError as err:
            # support for private module import
            if (NoSuchProcess is None or AccessDenied is None or
                    ZombieProcess is None):
                raise
            if err.errno == errno.ESRCH:
                if not pid_exists(self.pid):
                    raise NoSuchProcess(self.pid, self._name)
                else:
                    raise ZombieProcess(self.pid, self._name, self._ppid)
            if err.errno in (errno.EPERM, errno.EACCES):
                raise AccessDenied(self.pid, self._name)
            raise
    return wrapper


class Process(object):
    """Wrapper class around underlying C implementation."""

    __slots__ = ["pid", "_name", "_ppid"]

    def __init__(self, pid):
        """"Initialize the Process class with the given process ID and set the name and parent process ID to None.
        Parameters:
            - pid (int): The process ID to be assigned to the instance.
        Returns:
            - None: This function does not return anything.
        Processing Logic:
            - Set the process ID to the given pid.
            - Set the name to None.
            - Set the parent process ID to None."""
        
        self.pid = pid
        self._name = None
        self._ppid = None

    @wrap_exceptions
    def name(self):
        """"Returns the process name associated with the given process ID.
        Parameters:
            - pid (int): The process ID to retrieve the name for.
        Returns:
            - str: The name of the process associated with the given process ID.
        Processing Logic:
            - Uses cext.proc_name() to retrieve the process name.
            - Returns the process name as a string.""""
        
        return cext.proc_name(self.pid)

    @wrap_exceptions
    def exe(self):
        """Returns the execution of the process ID.
        Parameters:
            - self (object): The object containing the process ID.
        Returns:
            - str: The execution of the process ID.
        Processing Logic:
            - Uses the cext library to process the execution.
            - Returns the execution as a string."""
        
        return cext.proc_exe(self.pid)

    @wrap_exceptions
    def cmdline(self):
        """Returns the command line arguments used to launch the process with the given pid.
        Parameters:
            - pid (int): The process ID for which the command line arguments will be returned.
        Returns:
            - str: The command line arguments used to launch the process with the given pid.
        Processing Logic:
            - Uses the cext module to access the process's command line arguments.
            - Returns the command line arguments as a string.
            - Requires the process ID as input.
            - Does not modify the input."""
        
        return cext.proc_cmdline(self.pid)

    @wrap_exceptions
    def terminal(self):
        """"Returns the terminal associated with the process.
        Parameters:
            - self (object): The process object.
        Returns:
            - str: The terminal associated with the process, or None if not found.
        Processing Logic:
            - Get the process's tty number.
            - Get the mapping of tty numbers to terminals.
            - Return the terminal associated with the process's tty number, or None if not found.""""
        
        tty_nr = cext.proc_tty_nr(self.pid)
        tmap = _psposix._get_terminal_map()
        try:
            return tmap[tty_nr]
        except KeyError:
            return None

    @wrap_exceptions
    def ppid(self):
        """Returns the parent process ID of the current process.
        Parameters:
            - self (class): The current process.
        Returns:
            - int: The parent process ID.
        Processing Logic:
            - Get the parent process ID.
            - Use the pid attribute.
            - Call the cext library.
            - Use the proc_ppid function."""
        
        return cext.proc_ppid(self.pid)

    @wrap_exceptions
    def uids(self):
        """Function to retrieve the real, effective, and saved user IDs for a given process ID.
        Parameters:
            - pid (int): The process ID for which the user IDs are being retrieved.
        Returns:
            - tuple: A tuple containing the real, effective, and saved user IDs for the given process ID.
        Processing Logic:
            - Uses the cext module to retrieve the user IDs.
            - Calls the _common.puids function to format the returned values.
            - Returns a tuple of the user IDs."""
        
        real, effective, saved = cext.proc_uids(self.pid)
        return _common.puids(real, effective, saved)

    @wrap_exceptions
    def gids(self):
        """Returns:
            - list: A list of three elements representing the real, effective, and saved group IDs.
        Processing Logic:
            - Calls the cext.proc_gids() function.
            - Calls the _common.pgids() function.
            - Returns the result of _common.pgids()."""
        
        real, effective, saved = cext.proc_gids(self.pid)
        return _common.pgids(real, effective, saved)

    @wrap_exceptions
    def cpu_times(self):
        """Returns:
            - pcputimes: Returns a named tuple of user and system CPU times.
        Processing Logic:
            - Get user and system CPU times.
            - Convert to named tuple.
            - Return named tuple."""
        
        user, system = cext.proc_cpu_times(self.pid)
        return _common.pcputimes(user, system)

    @wrap_exceptions
    def memory_info(self):
        """"Returns the resident set size (rss) and virtual memory size (vms) of the process with the given pid.
        rss is the amount of physical memory used by the process, while vms is the total amount of virtual memory used by the process.
        Both values are returned in bytes.
        If the process does not exist, returns None for both values.
        Parameters:
            - pid (int): The process ID of the process to retrieve memory information for.
        Returns:
            - rss (int): The resident set size (rss) of the process in bytes.
            - vms (int): The virtual memory size (vms) of the process in bytes.
        Processing Logic:
            - Uses the cext.proc_memory_info() function to retrieve the rss and vms values.
            - Only the first two values are used, so the [:2] index is used to select them.
            - The _common.pmem() function is used to convert the values to bytes.
            - If the process does not exist, returns None for both values.""""
        
        rss, vms = cext.proc_memory_info(self.pid)[:2]
        return _common.pmem(rss, vms)

    @wrap_exceptions
    def memory_info_ex(self):
        """"Returns the extended memory information for the given process ID.
        Parameters:
            - self (type): Instance of the class.
            - pid (int): Process ID of the process to retrieve memory information for.
        Returns:
            - pextmem (tuple): A tuple containing the extended memory information for the given process ID.
        Processing Logic:
            - Calls the proc_memory_info function from the cext module.
            - Passes the process ID as a parameter to the proc_memory_info function.
            - Uses the pextmem function to return the extended memory information for the given process ID.
            - Returns a tuple containing the extended memory information.
        Example:
            - memory_info_ex(self, 1234) # Returns the extended memory information for process ID 1234.""""
        
        return pextmem(*cext.proc_memory_info(self.pid))

    @wrap_exceptions
    def create_time(self):
        """"Returns the process creation time for the given process ID.
        Parameters:
            - pid (int): The process ID to retrieve the creation time for.
        Returns:
            - float: The process creation time in seconds since the epoch.
        Processing Logic:
            - Uses cext.proc_create_time() to retrieve the creation time.
            - Returns the time in seconds since the epoch.""""
        
        return cext.proc_create_time(self.pid)

    @wrap_exceptions
    def num_threads(self):
        """This function returns the number of threads associated with a given process.
        Parameters:
            - pid (int): The process ID of the process.
        Returns:
            - int: The number of threads associated with the process.
        Processing Logic:
            - Calls the cext.proc_num_threads function.
            - Returns the number of threads.
            - Uses the process ID to identify the process."""
        
        return cext.proc_num_threads(self.pid)

    @wrap_exceptions
    def num_ctx_switches(self):
        """"Returns the number of context switches for the given process ID.
        Parameters:
            - pid (int): The process ID to retrieve context switches for.
        Returns:
            - int: The number of context switches for the given process ID.
        Processing Logic:
            - Uses the cext module to retrieve the number of context switches.
            - Calls the _common.pctxsw function to format the result.
            - Returns the formatted result.
        Example:
            num_ctx_switches(123) # Returns 50""""
        
        return _common.pctxsw(*cext.proc_num_ctx_switches(self.pid))

    @wrap_exceptions
    def threads(self):
        """Returns a list of thread information for the given process ID.
        Parameters:
            - pid (int): The process ID to retrieve thread information for.
        Returns:
            - list: A list of _common.pthread namedtuples containing thread ID, user time, and system time.
        Processing Logic:
            - Retrieve raw thread information using cext.proc_threads().
            - Convert raw thread information into _common.pthread namedtuples.
            - Append each namedtuple to a list.
            - Return the list of namedtuples."""
        
        rawlist = cext.proc_threads(self.pid)
        retlist = []
        for thread_id, utime, stime in rawlist:
            ntuple = _common.pthread(thread_id, utime, stime)
            retlist.append(ntuple)
        return retlist

    @wrap_exceptions
    def connections(self, kind='inet'):
        """"Returns a list of network connections of the specified kind for the given process ID.
        Parameters:
            - self (object): The object representing the process.
            - kind (str): The type of connection to retrieve. Defaults to 'inet'. Valid options are 'inet', 'inet6', 'tcp', 'tcp6', 'udp', 'udp6', 'unix', 'all'.
        Returns:
            - list: A list of network connections, each represented as a named tuple with the following fields: fd (int), family (int), type (int), local address (str), remote address (str), and status (str).
        Processing Logic:
            - Validates the specified kind argument.
            - Retrieves the list of connections using the specified process ID and connection types.
            - Converts the raw data into a list of named tuples.
            - Returns the list of connections.""""
        
        if kind not in conn_tmap:
            raise ValueError("invalid %r kind argument; choose between %s"
                             % (kind, ', '.join([repr(x) for x in conn_tmap])))
        families, types = conn_tmap[kind]
        rawlist = cext.proc_connections(self.pid, families, types)
        ret = []
        for item in rawlist:
            fd, fam, type, laddr, raddr, status = item
            fam = sockfam_to_enum(fam)
            type = socktype_to_enum(type)
            status = TCP_STATUSES[status]
            nt = _common.pconn(fd, fam, type, laddr, raddr, status)
            ret.append(nt)
        return ret

    @wrap_exceptions
    def wait(self, timeout=None):
        """Function:
        def wait(self, timeout=None):
            Waits for the process to finish and returns the exit code.
            Parameters:
                - timeout (float): Maximum number of seconds to wait for the process to finish.
            Returns:
                - int: The exit code of the process.
            Processing Logic:
                - Waits for the process to finish.
                - Returns the exit code.
                - Raises TimeoutExpired if the process does not finish within the specified timeout."""
        
        try:
            return _psposix.wait_pid(self.pid, timeout)
        except _psposix.TimeoutExpired:
            # support for private module import
            if TimeoutExpired is None:
                raise
            raise TimeoutExpired(timeout, self.pid, self._name)

    @wrap_exceptions
    def nice_get(self):
        return cext_posix.getpriority(self.pid)

    @wrap_exceptions
    def nice_set(self, value):
        return cext_posix.setpriority(self.pid, value)

    @wrap_exceptions
    def status(self):
        code = cext.proc_status(self.pid)
        if code in PROC_STATUSES:
            return PROC_STATUSES[code]
        # XXX is this legit? will we even ever get here?
        return "?"

    @wrap_exceptions
    def io_counters(self):
        rc, wc, rb, wb = cext.proc_io_counters(self.pid)
        return _common.pio(rc, wc, rb, wb)

    nt_mmap_grouped = namedtuple(
        'mmap', 'path rss, private, ref_count, shadow_count')
    nt_mmap_ext = namedtuple(
        'mmap', 'addr, perms path rss, private, ref_count, shadow_count')

    # FreeBSD < 8 does not support functions based on kinfo_getfile()
    # and kinfo_getvmmap()
    if hasattr(cext, 'proc_open_files'):

        @wrap_exceptions
        def open_files(self):
            """Return files opened by process as a list of namedtuples."""
            rawlist = cext.proc_open_files(self.pid)
            return [_common.popenfile(path, fd) for path, fd in rawlist]

        @wrap_exceptions
        def cwd(self):
            """Return process current working directory."""
            # sometimes we get an empty string, in which case we turn
            # it into None
            return cext.proc_cwd(self.pid) or None

        @wrap_exceptions
        def memory_maps(self):
            return cext.proc_memory_maps(self.pid)

        @wrap_exceptions
        def num_fds(self):
            """Return the number of file descriptors opened by this process."""
            return cext.proc_num_fds(self.pid)

    else:
        def _not_implemented(self):
            raise NotImplementedError("supported only starting from FreeBSD 8")

        open_files = _not_implemented
        proc_cwd = _not_implemented
        memory_maps = _not_implemented
        num_fds = _not_implemented

    @wrap_exceptions
    def cpu_affinity_get(self):
        return cext.proc_cpu_affinity_get(self.pid)

    @wrap_exceptions
    def cpu_affinity_set(self, cpus):
        # Pre-emptively check if CPUs are valid because the C
        # function has a weird behavior in case of invalid CPUs,
        # see: https://github.com/giampaolo/psutil/issues/586
        allcpus = tuple(range(len(per_cpu_times())))
        for cpu in cpus:
            if cpu not in allcpus:
                raise ValueError("invalid CPU #%i (choose between %s)"
                                 % (cpu, allcpus))
        try:
            cext.proc_cpu_affinity_set(self.pid, cpus)
        except OSError as err:
            # 'man cpuset_setaffinity' about EDEADLK:
            # <<the call would leave a thread without a valid CPU to run
            # on because the set does not overlap with the thread's
            # anonymous mask>>
            if err.errno in (errno.EINVAL, errno.EDEADLK):
                for cpu in cpus:
                    if cpu not in allcpus:
                        raise ValueError("invalid CPU #%i (choose between %s)"
                                         % (cpu, allcpus))
            raise
