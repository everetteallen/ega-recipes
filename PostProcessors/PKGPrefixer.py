#!/usr/bin/python
#
# Copyright 2020 Everette Allen
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# vars for testing:
# pkg_name "Google Chrome-89.0.4389.82.pkg"
# pkg_path "/Users/user/Library/AutoPkg/Cache/Google Chrome-89.0.4389.82.pkg"
# pkg_prefix "UNCWide-AutoPkg-"
#

from __future__ import absolute_import, print_function

import os
from autopkglib import Processor, ProcessorError  # pylint: disable=import-error

__all__ = ["PKGPrefixer"]


class PKGPrefixer(Processor):
    description = (
        "Adds a prefix string from pkg_prefix varialbe to a PKG "
    )
    input_variables = {
         "pkg_name": {
            "required": False,
            "description": "Package name. If supplied, will rename the package supplied "
            "in the pkg_path key.",
            "default": "",
        },
        "pkg_path": {
            "required": True,
            "description": "Path to a pkg or dmg to import - provided by "
            "previous pkg recipe/processor.",
            "default": "",
        },
        "pkg_prefix": {
            "required": True,
            "description": "String to prefix packge name with",
            "default": "",
        }
    }
    output_variables = {
        "pkg_path": {
            "description": "The path of the renamed package.",
        },
        "pkg_name": {
            "description": "The name of the prefixed package."
        },
        "pkg_prefixer_summary_result": {
            "description": "Description of interesting results.",
        },
    }
    __doc__ = description
      

    def main(self):   
        # try to get the package prefix from the environment
        self.pkg_prefix = self.env.get("pkg_prefix")
        if not self.pkg_prefix:
            print(f'No Prefix to add.')
            return
        
        # try to get the package path
        self.pkg_path = self.env.get("pkg_path")
        if not self.pkg_path:
            try:
                pathname = self.env.get("pathname")
                if pathname.endswith(".pkg"):
                    self.pkg_path = pathname
            except KeyError:
                pass
        
        # try to get the package name
        self.pkg_name = self.env.get("pkg_name")
        if not self.pkg_name:
            self.pkg_name = os.path.basename(self.pkg_path)
        
        # try to get the directory the package is in
        self.path_name = os.path.dirname(self.pkg_path)
        
        # form the full path with new prefix
        self.pkg_name = self.pkg_prefix + self.pkg_name
        self.prefix_path = self.path_name + "/" + self.pkg_name

        # try to rename the package using full paths
        try:
            os.rename(self.pkg_path, self.prefix_path)
        except KeyError:
            pass
        
         # output the summary
        self.env["pkg_name"] = self.pkg_name
        self.env["pkg_path"] = self.prefix_path
        self.env["pkg_prefixer_summary_result"] = {
            "summary_text": "The following package was renamed:",
            "report_fields": ["pkg_path", "pkg_name"],
            "data": {
                "pkg_path": self.pkg_path,
                "pkg_name": self.pkg_name,
            },
        }



if __name__ == "__main__":
    processor = PKGPrefixer()
    processor.execute_shell()
