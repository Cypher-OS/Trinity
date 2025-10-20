Trinity — Init System and Service Manager
=

Trinity is a lightweight, dependency-aware init system and service manager designed for minimal overhead and robust boot management.<br>
It functions as the PID 1 process on Cypher, handling system initialization, service supervision, and process control.

## Key Features<br>
-**1. PID 1 (Init System)** <br>

-**2. Dual Boot Mode** <br>
Trinity supports two distinct, selectable boot profiles:<br>
--**Persistent Mode: Standard boot. Data is persistent and saved on disk.** <br>
--**Ephemeral Mode: All writes and modifications vanish on reboot** <br>

-**3. Service Management** <br>

# Commands
```rsh
sudo trinity start <service>

sudo trinity stop <service>

sudo trinity restart <service>

sudo trinity status <service>

trinity shutdown

trinity reboot
```

-**4. Dependency-Aware Management and Start Order** <br>

-**5. Minimalism** <br>

