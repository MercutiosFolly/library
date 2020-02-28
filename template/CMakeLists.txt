cmake_minimum_required(VERSION 3.5)
project( My_Project
  LANGUAGES CXX
  VERSION 0.1 
  DESCRIPTION "Template Project"
)

###########################
# Prevent In-Source Build
###########################
if( "${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
  message(FATAL_ERROR "FATAL: In-source builds are not allowed.
       You should create a separate directory for build files.")
endif()

###########################
# Settings
###########################
set( CMAKE_BUILD_TYPE Debug )
set( BINARY_NAME my-project )
set( INSTALL_LOCATION "/usr/local/src" )

set( MY_DEBUG_FLAGS -Wall -Wextra -Werror -g )
set( MY_RELEASE_FLAGS -Wpedantic -03 )
set( CMAKE_CSS_STANDARD 11 )
set( CMAKE_CSS_STANDARD_REQUIRED ON )

set( SRC_FILES
)
set( INCLUDE_DIRS
)

###########################
# Packages
###########################

# PCL
find_package( PCL 1.9 REQUIRED COMPONENTS common visualization io )

# Boost
find_package( Boost REQUIRED COMPONENTS thread )


###########################
# Build
###########################
add_executable( ${BINARY_NAME}
  ${SRC_FILES}
)

set_target_properties( ${BINARY_NAME}
  VERSION ${PROJECT_VERSION}
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin"
)

target_compile_options( ${BINARY_NAME}
  PRIVATE
  "$<$<CONFIG:DEBUG>:${MY_DEBUG_FLAGS}>"
  "$<$<CONFIG:RELEASE>:${MY_RELEASE_FLAGS}>"
)

target_include_directories( ${BINARY_NAME}
  PRIVATE
  ${INCLUDE_DIRS}
)

target_link_libraries( ${BINARY_NAME}
  ${PCL_LIBRARIES}
  ${Boost_LIBRARIES}
)

###########################
# Install
###########################
install( ${BINARY_NAME}
  DESTINATION ${INSTALL_LOCATION}
)

