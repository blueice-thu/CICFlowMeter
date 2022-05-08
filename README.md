# CICFlowMeter

**Too many bugs in this project.**

**Do not advise to use this project.**

**Recommend: https://github.com/blueice-thu/kdd99_feature_extractor**

## Dependencies

- libpcap (for linux) or winpcap (for windows)
- tcpdump

#### Install jnetpcap local repo

for linux, sudo is a prerequisite
```bash
//linux :at the pathtoproject/jnetpcap/linux/jnetpcap-1.4.r1425
//windows: at the pathtoproject/jnetpcap/win/jnetpcap-1.4.r1425
mvn install:install-file -Dfile=./jnetpcap/linux/jnetpcap-1.4.r1425/jnetpcap.jar -DgroupId=org.jnetpcap -DartifactId=jnetpcap -Dversion=1.4.r1425 -Dpackaging=jar
```

Introduction about JnetPcap: https://www.geeksforgeeks.org/packet-capturing-using-jnetpcap-in-java/

For Windows: (x64)
1. Download and Install the latest stable version of JRE and JDK for Windows 64 bits.
2. Download and Install the latest stable version of Eclipse for Windows 64 bit.
3. Download stable release of jNetPcap (for 64 bit Windows) from http://jnetpcap.com/download.
4. Extract .rar file.
5. After extraction, copy its data link library (jnetpcap.dll) to the system32 folder with administrative permission.
6. Now open Eclipse, create the project. right click on the project, go to properties, go to java build path, click on Add External jars and provide the path to jnetpcap.jar.
7. Write a program and run.

For Linux: (x64)
1. Prefer Ubuntu 14.04 or 16, .04 (Stable release). It contains java as default with OS installation.
2. Install eclipse-full which will automatically install the latest supported java if it is not found. (from the command line or from software centre)
3. Install g++ and libpcap-dev (from the command line as it does not comes in the software center if it not an updated one).
4. Download stable release of jNetPcap (for 64 bit Linux) from http://jnetpcap.com/download.
5. Extract .rar file.
6. After extraction, copy libjnetpcap.so and libjnetpcap-pcap100.so in /usr/lib/ (as sudo).
7. Now open Eclipse, create the project. right click on the project, go to properties, go to java build path, click on Add External jars and provide the path to jnetpcap.jar.
8. Write a program and run.

## Run GUI

```
//linux:
$ sudo bash
$ ./gradlew execute

//windows:
$ gradlew execute
```

## Make package

```
//linux:
$ ./gradlew distZip
//window
$ gradlew distZip
```
the zip file will be in the `pathtoproject/CICFlowMeter/build/distributions`

## Usage

```bash
./cfm [pcap_path_file.pcap] [output_dir]
```
