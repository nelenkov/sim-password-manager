APPLET_AID      = 0x73:0x69:0x6d:0x70:0x61:0x73:0x73:0x6d:0x61:0x6e:0x01
APPLET_NAME     = org.nick.passman.sim.PasswordManagerApplet
PACKAGE_AID     = 0x73:0x69:0x6d:0x70:0x61:0x73:0x73:0x6d:0x61:0x6e
PACKAGE_NAME    = org.nick.passman.sim
PACKAGE_VERSION = 1.0

SOURCES = \
	src/org/nick/passman/sim/JavaCardAES.java \
	src/org/nick/passman/sim/PasswordManagerApplet.java

BUILD_DIR           = ./build
BUILD_CLASSES_DIR   = $(BUILD_DIR)/classes
BUILD_JAVACARD_DIR  = $(BUILD_DIR)/javacard
JAVACARD_SDK_DIR    ?= /home/javacard
JAVACARD_EXPORT_DIR ?= $(JAVACARD_SDK_DIR)/api21_export_files
ifdef COMSPEC
	CLASSPATH	    = $(JAVACARD_SDK_DIR)/lib/api21.jar;$(JAVACARD_SDK_DIR)/lib/sim.jar
else
	CLASSPATH           = $(JAVACARD_SDK_DIR)/lib/api21.jar:$(JAVACARD_SDK_DIR)/lib/sim.jar
endif
JFLAGS              = -target 1.1 -source 1.3 -g -d $(BUILD_CLASSES_DIR) -classpath "$(CLASSPATH):$(BUILD_CLASSES_DIR)"
JAVA                ?= java
JC                  ?= javac

.SUFFIXES: .java .class
.java.class:
	mkdir -p $(BUILD_CLASSES_DIR)
	mkdir -p $(BUILD_JAVACARD_DIR)

	$(JC) $(JFLAGS) $(SOURCES)

	$(JAVA) -jar $(JAVACARD_SDK_DIR)/bin/converter.jar  \
		-d $(BUILD_JAVACARD_DIR)                    \
		-classdir $(BUILD_CLASSES_DIR)              \
		-exportpath $(JAVACARD_EXPORT_DIR)          \
		-applet $(APPLET_AID) $(APPLET_NAME)        \
		$(PACKAGE_NAME) $(PACKAGE_AID) $(PACKAGE_VERSION)

default: classes

classes: $(SOURCES:.java=.class)

clean:
	$(RM) -rf $(BUILD_DIR)

