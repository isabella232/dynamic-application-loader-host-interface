/*
   Copyright 2010-2016 Intel Corporation

   This software is licensed to you in accordance
   with the agreement between you and Intel Corporation.

   Alternatively, you can use this file in compliance
   with the Apache license, Version 2.


   Apache License, Version 2.0

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#ifndef _JHI_VERSION_H_
#define _JHI_VERSION_H_

#ifdef __cplusplus
extern "C" {
#endif

#define _MAKE_VER_STRING(v1, v2, v3, v4)    #v1 "." #v2 "." #v3 "." #v4
#define MAKE_VER_STRING(v1, v2, v3, v4)    _MAKE_VER_STRING(v1, v2, v3, v4)

// Version format: Major.Minor.Year.MonthDay
#define JHI_VER_MAJOR    1
#define JHI_VER_MINOR    41
#define JHI_VER_YEAR     2021
#define JHI_VER_MONTHDAY 0121


#define JHI_VERSION MAKE_VER_STRING(JHI_VER_MAJOR, JHI_VER_MINOR, JHI_VER_YEAR, JHI_VER_MONTHDAY)

#define VER_PRODUCTVERSION          JHI_VER_MAJOR,JHI_VER_MINOR,JHI_VER_YEAR,JHI_VER_MONTHDAY
#define VER_PRODUCTVERSION_STR      MAKE_VER_STRING(JHI_VER_MAJOR, JHI_VER_MINOR, JHI_VER_YEAR, JHI_VER_MONTHDAY)

/**  Adding the current year date string for use in updating the year component of the 
***  displayed copyright message.
***  the string needs to be the full 4 char value without spaces or special characters.
***  For example:
***        "2012"
*/
#define CURRENT_YEAR_STRING   "2021"

/* Global Declarations
 **************************/

#define VER_SEPARATOR_STR "."   /**< Separator String used between major, minor, hotfix and build strings */
/** @brief Defines a generic version structure used in the software build process. This structure will be used to
*   represent versions of ROM, FW and Recovery modules.
*/
typedef struct _VERSION
{
   UINT16      Major;
   UINT16      Minor;
   UINT16      Hotfix;
   UINT16      Build;
}VERSION;

#ifdef __cplusplus
}
#endif

/* Global Functions
 **************************/

#endif // _VER_H_

