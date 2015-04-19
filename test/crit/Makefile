loop:
	gcc -g $@.c -o $@
	chmod +x $@

run: clean loop
	./test.sh

clean:
	rm -f *.img *.log *.txt stats-* *.json loop core.*
