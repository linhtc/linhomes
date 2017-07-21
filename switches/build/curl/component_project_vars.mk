# Automatically generated build file. Do not edit.
COMPONENT_INCLUDES += $(IDF_PATH)/components/curl/port/include $(IDF_PATH)/components/curl/include
COMPONENT_LDFLAGS += -L$(BUILD_DIR_BASE)/curl -lcurl
COMPONENT_LINKER_DEPS += 
COMPONENT_SUBMODULES += 
COMPONENT_LIBRARIES += curl
curl-build: 
