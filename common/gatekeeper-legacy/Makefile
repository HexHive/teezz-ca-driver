
.PHONY: build run clean

build:
	@javac -source 1.7 -target 1.7 GatekeeperClient.java
	@dx --dex --output=classes.dex GatekeeperClient.class
	@zip GatekeeperClient.zip classes.dex

run: build
	@adb push GatekeeperClient.zip /data/local/tmp/
	adb shell "su -c CLASSPATH=/data/local/tmp/GatekeeperClient.zip app_process /data/local/tmp/ GatekeeperClient"

run-dalvik: build
	@adb push GatekeeperClient.zip /data/local/tmp/
	@adb shell "su -c setenforce 0"
	adb shell "su -c dalvikvm -verbose:class,jit -Xzygote -XXlib:libart.so -Xnorelocate -classpath /data/local/tmp/GatekeeperClient.zip GatekeeperClient"

clean:
	$(RM) *.class *.dex *.zip
