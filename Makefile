all: TpDNS.class

TpDNS.class: TpDNS.java
	javac $^

clean:
	rm -rf *.class *~
