Trinity — Init System and Service Manager
=

Trinity is a lightweight, dependency-aware init system and service manager designed for minimal overhead and robust boot management.<br>
It functions as the PID 1 process on Cypher, handling system initialization, service supervision, and process control.

Key Features<br>
**1. PID 1 (Init System)** <br>

As PID 1, Trinity is the first process spawned by the kernel.<br>
It is responsible for starting all other system services and processes.<br>
It also adopts orphaned processes and “reaps” them, preventing zombie processes from consuming system resources.<br>

**2. Dual Boot Mode** <br>

Trinity supports two distinct, selectable boot profiles:<br>

**Persistent Mode:** <br>
The traditional mode where services and configurations are loaded from standard system directories (e.g., /etc, /usr/lib).<br>
Changes made to the system (e.g., installing software, modifying configs) persist across reboots.<br>

**Ephemeral Mode:** <br>
A minimal, stateless boot mode where the system mounts a temporary filesystem for configuration and runtime data.<br>
Changes are discarded on shutdown — ideal for testing, secure environments, or rapid deployments.<br>
Core system files typically remain read-only.<br>

**3. Service Management** <br>

Trinity provides a robust and simple framework for controlling system services.<br>

Standard Operations: Clean commands for starting, stopping, restarting, reloading, and checking the status of services.<br>
Service Supervision: Continuously monitors running services. If a service crashes, Trinity can automatically restart it based on configuration.<br>

**4. Dependency-Aware Management and Start Order** <br>

Ensures a reliable and efficient system startup sequence.<br>

Dependency Resolution: Services can declare dependencies (e.g., a web server depends on networking). Trinity reads configurations to determine proper order.<br>
Correct Start Order: Services only start once their dependencies are fully operational — preventing race conditions and boot failures, while improving startup performance.<br>

**5. Minimalism** <br>

Trinity follows a strict minimal design philosophy.<br>

Low Overhead: Small memory and CPU footprint — ideal for embedded or resource-limited systems.<br>
Focus on Core Functionality: Only essential service and system management tasks are included, maintaining simplicity, speed, and reliability.<br>
