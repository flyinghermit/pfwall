obj-m += kpfwall.o
kpfwall-objs := pfwall_module.o pfwall_public.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -Wall -Wextra pfwall_admin.c pfwall_public.c -o ./pfwall_admin

admin:
	gcc -Wall -Wextra pfwall_admin.c pfwall_public.c -o ./pfwall_admin

module:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f ./pfwall_admin
