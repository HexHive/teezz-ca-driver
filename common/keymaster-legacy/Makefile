
.PHONY: build run clean

build:
	@javac -nowarn -source 1.7 -target 1.7 \
	  *.java
	
	@dx --dex --output=classes.dex \
	  *.class
	
	@zip KeystoreClient.zip \
	  classes.dex

run: build
	@adb push KeystoreClient.zip /data/local/tmp/ > /dev/null
	@adb shell "su -c setenforce 0"
	@adb shell "su 1000 -c CLASSPATH=/data/local/tmp/KeystoreClient.zip app_process /data/local/tmp/ Tests 0"
	@adb shell "su 1000 -c CLASSPATH=/data/local/tmp/KeystoreClient.zip app_process /data/local/tmp/ Tests 1"
	@adb shell "su 1000 -c CLASSPATH=/data/local/tmp/KeystoreClient.zip app_process /data/local/tmp/ Tests 2"
	@adb shell "su 1000 -c CLASSPATH=/data/local/tmp/KeystoreClient.zip app_process /data/local/tmp/ Tests 3"
	@adb shell "su 1000 -c CLASSPATH=/data/local/tmp/KeystoreClient.zip app_process /data/local/tmp/ Tests 4"
	@adb shell "su 1000 -c CLASSPATH=/data/local/tmp/KeystoreClient.zip app_process /data/local/tmp/ Tests 5"
	@adb shell "su 1000 -c CLASSPATH=/data/local/tmp/KeystoreClient.zip app_process /data/local/tmp/ Tests 6"
	@adb shell "su 1000 -c CLASSPATH=/data/local/tmp/KeystoreClient.zip app_process /data/local/tmp/ Tests 7"
	@adb shell "su 1000 -c CLASSPATH=/data/local/tmp/KeystoreClient.zip app_process /data/local/tmp/ Tests 8"


clean:
	$(RM) *.class *.dex *.zip
