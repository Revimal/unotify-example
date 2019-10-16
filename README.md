# unotify-example

This is a sample kernel module which to schedule user-processes.

You can get a file descriptor of the module with calling `open()` to `/dev/unotify`.

It has the following two operations that can be accessed with `ioctl()` syscall.
* Block the current process: You can block the current user-process with `ioctl( unotify_fd, 0, 0 );`.
* Wake the specific process: You can wake the specific user-process with `ioctl( unotify_fd, 1, remote_pid );`.

Issues can be reported on [Github Issue Tracker](https://github.com/Revimal/unotify-example/issues).

All contents in this repository are licensed under an [MIT/GPL Dual License](https://github.com/Revimal/unotify-example/blob/master/LICENSE).
