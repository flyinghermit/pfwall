
# proxy firewall
netfilter firewall with http proxy. can be used as combined firewall to manage layer 3 and layer 7 packets. filtering based on four tuple array of port and ip address. have dynamic IP of target or want to block specific domain? use proxy server to filter domain names. built as part of course work. 
 
### NOTE
*Please check kernel header syscall.32 and syscall.64 before installing this program. they must me somewhere inside linux header/arch/syscall. 
they are required to build every kernel module. It must be there by default but most of the time you have to install it there
These samples command usage are tested. ofcourse there are more possible way to make rules.*

I tested this on my linux box(ubuntu-3.8.0-35-generic) 
but should work on every distribution.
you should be root in order to exexute these commands. Use sudo before every command(preferable) 

```
1) Drop all UDP traffic => # ./pfwall_admin --proto UDP
2) Drop all UDP traffic to/from port 53 => # ./pfwall_admin --proto UDP --dstport 53
3) Allow all TCP traffic coming from 1.2.3.4:80 => # ./pfwall_admin --action PASS --proto TCP --direction IN --srcip 1.2.3.4 --srcport 80
4) Allow outgoing traffic to port 80 => # ./pfwall_admin --action PASS --dstport 80
5) Delete rule number 33 => # ./pfwall_admin --delete 33
6) List all rules. => # ./pfwall_admin --list
```



