JC = javac                 

all: SendUDP.class

SendUDP.class: SendUDP.java
	$(JC) $^

clean:
	rm -rf *.class *~
