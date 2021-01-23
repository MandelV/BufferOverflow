install:
	gcc -fno-stack-protector -m32 -o overflow main.c
	sudo chown root:root overflow
	sudo chmod +s overflow
	sudo bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space'
exploit:
	python3 exploit.py
