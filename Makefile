all: SendUDP.class

SendUDP.class: SendUDP.java
	javac $^

clean:
	rm -rf *.class *~
