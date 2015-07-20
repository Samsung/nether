#
#  Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
#
#  Contact: Roman Kubiak (r.kubiak@samsung.com)
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License
#

FIND_PATH (AUDIT_INCLUDE_DIR libaudit.h /usr/include /usr/local/include)
FIND_LIBRARY (AUDIT_LIBRARY NAMES libaudit.a PATH /usr/lib /usr/local/lib)

IF (AUDIT_INCLUDE_DIR AND AUDIT_LIBRARY)
   SET (AUDIT_FOUND TRUE)
ENDIF (AUDIT_INCLUDE_DIR AND AUDIT_LIBRARY)


IF (AUDIT_FOUND)
   IF (NOT audit_FIND_QUIETLY)
      MESSAGE(STATUS "Found audit: ${AUDIT_LIBRARY}")
   ENDIF (NOT audit_FIND_QUIETLY)
ELSE (AUDIT_FOUND)
   IF (audit_FIND_REQUIRED)
      MESSAGE(FATAL_ERROR "Could not find audit")
   ENDIF (audit_FIND_REQUIRED)
ENDIF (AUDIT_FOUND)
