cropped out part of a once working cheat

- callback removal (process, thread, imagenotify, object create) by patching the target callback
- memory read/write
- manual handle creation by iterating handle table
- basic communication (ioctl)
- optionally, you can enable features that require ssdt hooks (you need to disable patchguard in your preferred way)
- utility helper functions
