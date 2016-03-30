# nether

An application firewall that enforces the "internet"
privileges in Tizen. It uses Cynara as a policy backend
and the NFQUEUE target in netfilter to make decisiions
about outgoing connections and network packets.

The policy backend can be re-implemented by overloading
the NetherPolicyBackend class (there is a simple File based
backend included for testing).

A default policy can be specified in case the policy
backend stops working.

```
Usage: nether [OPTIONS]

  -d,--daemon				Run as daemon in the background (default:no)
  -x,--no-rules				Don't load iptables rules on start (default:no)
  -c,--copy-packets			Copy entire packets, needed to read TCP/IP information (default:no)
  -I,--interface-info			Get interface info for every packet (default:no)
  -R,--relaxed				Run in relaxed mode, instrad of deny do ACCEPT_LOG(default:no)
  -l,--log=<backend>			Set logging backend STDERR,SYSLOG(default:stderr)
  -L,--log-args=<arguments>		Set logging backend arguments
  -V,--verdict=<verdict>		What verdict to cast when policy backend is not available
					ACCEPT,ALLOW_LOG,DENY (default:ALLOW_LOG)
  -p,--primary-backend=<module>		Primary policy backend
					CYNARA,FILE,NONE (defualt:cynara)
  -P,--primary-backend-args=<arguments>	Primary policy backend arguments
  -b,--backup-backend=<module>		Backup policy backend
					CYNARA,FILE,NONE (defualt:file)
  -B,--backup-backend-args=<arguments>	Backup policy backend arguments (default:/etc/nether/nether.policy)
  -q,--queue-num=<queue number>		NFQUEUE queue number to use for receiving packets (default:0)
  -m,--mark-deny=<mark>			Packet mark to use for DENY verdicts (default:3)
  -M,--mark-allow-log=<mark>		Packet mark to use for ALLOW_LOG verdicts (default:4)
  -a,--enable-audit			Enable the auditing subsystem (default: no)
  -r,--rules-path=<path>		Path to iptables rules file (default:/etc/nether/nether.rules)
  -i,--iptables-restore-path=<path>	Path to iptables-restore command (default:/usr/sbin/iptables-restore)
  -h,--help				show help information
```

## Backend arguments:

### cynara

(multiple parameters should be seperated with ';')

`policy=<file>` specifies a path to a file that defines cynara policy details, it can contain multiple privileges and special packet markings for them, this way you can can poke holes in your security policy.

`cache-size=<number>` size of the cynara cache to allocate (this unit is defined by cynara not by nether)

`privname=<privilege>` the name of the privilege to check in cynara, this is hard coded in nether but can be altered on the command line, this will only have affect in case a policy file is not defined, if a policy file exists the first privilege in that file is considered the default privilege


### file

There is just one argument that is the path to the location of the policy file.

## Details:
-x - by default nether loads iptables rules needed for nethet to catch packets it should make descisions about, the default set of rules can be found in CMAKE_INSTALL_PREFIX/etc/nether/nether.rules. Default rules catch first packets of each TCP/IP connection and ignore all traffic on the loopback interface. If you wish to change the default set of rules, edit this file. Or set the rules on your own and start nether with this option

-c - by default nether does not receive the entire network packet, it's not needed to get the meta information about a packet (UID/GID and the security context of each packet). But if you policy backend needs more information about the network specifc part of a packet, setting this option will provide TCP/IP information to the backend (destination and source interface if available, destination and source IP address, destination and source PORT if the protocol is TCP/UDP). This option is used to gain more performance if the policy backend does not require network information.

-I - same as -c but for network interface information

-R - this is a special mode where nether will work as usual (perform security checks against it's defined policy backends), but regardless of the response it will always ACCEPT all packets. This can be used for testing purposes.

-L - log backend arguments, the only backend that accepts options is the FILE backend, the option for it is the log file path.

-V - this is the fallback verdict that will be used in case ALL policy backends fail, or are unable to make decisions about a certain packet (due to lack of specific information or due to some type mismatch)

-p - set's the primary policy backend to use

-P - set's the primary backend args, currently two backends use this option The FILE backend uses this option for the file path where the policy is kept, by default this is set to ${CMAKE_INSTALL_DIR}/etc/nether/nether.policy The CYNARA backend uses this option to set the cache size that the client side will use, the size is in CYNARA specific units, the format is cache-size=NUM where NUM is the cache size, other options might appear in this field in the future

-b,-B - same as -p -P but for the backup policy backend

-q - This is the queue number that nether will accept packets from, the queue number is by default 0 and you can set it to a different number by editing your iptables rules. This number must match the queue number set by iptables.

-m,-M - iptables use theese values to mark packets as ACCEPT,DENY after nether made a decision about them. Those numbers must match the numbers set by iptables rules (by default they are 0x3 for DENY and 0x4 for ALLOW_LOG)

-a - if audit headers are available, nether will activate auditing on start

-r - the path to the default set of rules nether should apply on start, by default this is set to ${CMAKE_INSTALL_DIR}/etc/nether/nether.rules

-i - the path to the iptables-restore program, it's needed to set the initial nether rules. No api is provided by netfilter to set the rules. iptables-restore is a preferred way to restore rules in the system.

## Poking holes in cynara policy:

In order to exclude some traffic from the cynara policy, you can define custom privileges and paths they should take inside iptables. This is done by specifying a custom cynara.policy file with privilege|mark pairs. If a defined privilege gets a ALLOW response the packet that was beeing matched gets marked with the defined mark. Using the initial nether.rules you can add custom rules for those matched packets and do whatever you want with them.

There is one example debug privilege defined in the cynara.policy as an example, it doesn't do anything but if an application has this privilege and cynara returns ALLOW for it the traffic will pass. This means that an application does not need the default internet privilege. You can define as many privilege|mark pairs as you wish, all entries will be processed until at least one returns ALLOW, in case all return DENY the traffic will be blocked.
