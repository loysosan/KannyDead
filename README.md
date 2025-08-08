![Kenny](kenny.png)

# icmpshell

**WARNING!**

> ⚠️ **This project is an educational test rootkit for the Linux kernel.**
> 
> ⚠️ **DO NOT use this code in production or on live systems!**
> 
> ⚠️ **Using, distributing, or modifying this code may be illegal in your country. You act at your own risk!**
> 
> ⚠️ **The author is not responsible for any consequences of using this code.**

---

## Description

`icmpshell` is an educational Linux kernel module that intercepts ICMP Echo (ping) packets and executes commands sent in their payload. The command must start with the prefix `run:`. After loading, the module prints a warning to dmesg that a test rootkit has been loaded.

### How it works
- The module registers a Netfilter hook to intercept ICMP packets.
- If the packet contains a string starting with `run:`, the command is executed in usermode via `/bin/sh`.
- All other packets are ignored.
- When loaded, the module prints a warning to the system log (dmesg).
- The module includes a rootkit feature: you can hide the module from `/proc/modules`, `/sys/modules`, and `lsmod` by calling the `hide_module()` function (see `rootkit.h`).

### Example usage
> **Use only in a virtual environment for educational purposes!**

1. Build the module:
   ```sh
   make
   ```
2. Load the module (root privileges required):
   ```sh
   sudo insmod icmpshell.ko
   ```
3. Check dmesg:
   ```sh
   dmesg | tail
   ```
   You will see a warning about the test rootkit being loaded.

4. Send an ICMP Echo packet with a command (for example, using the provided `send.py` script).

5. (Optional) To hide the module, call `hide_module()` from your code. To show it again, call `show_module()`.

### Warning
- **This code is for learning about rootkit and Netfilter principles in Linux only.**
- **Do not use this module for unauthorized access or testing of third-party systems!**
- **Use only in a controlled environment (e.g., a virtual machine).**
- **Remove the module after testing:**
  ```sh
  sudo rmmod icmpshell
  ```

---

## Author

Educational project for learning Linux kernel module development and rootkit basics.

---

**Once again: this code is for educational purposes only!**
