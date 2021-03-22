#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2017 Graham Pugh
# Copyright 2019 Matthew Warren / haircut
# Copyright 2020 Everette Allen 
#
# Based on the 'Slacker' PostProcessor by Graham R Pugh
# https://grahamrpugh.com/2017/12/22/slack-for-autopkg-jssimporter.html
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


from __future__ import absolute_import, print_function

import requests
from datetime import datetime

from autopkglib import Processor, ProcessorError

# Set the webhook_url to the one provided by Hangouts Chat
# See https://developers.google.com/hangouts/chat/how-tos/webhooks
__all__ = ["HangoutsChatJPUNotifier"]

class HangoutsChatJPUNotifier(Processor):
    description = ("Posts a Card notification to a Hangouts Chat room"
                   "via webhook based on output of a JamfPackageUploader run.")
    input_variables = {
        "JSS_URL": {
            "required": False,
            "description": ("JSS_URL.")
        },
        "category": {
            "required": False,
            "description": ("Package Category.")
        },
        "version": {
            "required": False,
            "description": ("Package Version.")
        },
        "pkg_name": {
            "required": False,
            "description": ("Title (NAME)")
        },
        "pkg_path": {
            "required": False,
            "description": ("The created package.")
        },
        "hangoutschatjpu_webhook_url": {
            "required": False,
            "description": ("Hangouts Chat webhook url.")
        },
        "hangoutschatjpu_should_report": {
            "required": False,
            "description": ("Hangouts Chat Notifier should always report or not.")
        }
    }
    output_variables = {
    }

    __doc__ = description

    def main(self):
        JSS_URL = self.env.get("JSS_URL")
        webhook_url = self.env.get("hangoutschatjpu_webhook_url")
        bugged = False
        
        #get the local time 
        now = datetime.now()
        self.pkg_date = date_time = now.strftime("%m/%d/%Y, %H:%M:%S")
        
        try:
            should_report = self.env.get("hangoutschatjpu_should_report")
        except:
            should_report = False
        
        # JPU Summary
        try:
            version = self.env.get("version")
            category = self.env.get("pkg_category")
            pkg_name = self.env.get("pkg_name")
            pkg_path = self.env.get("pkg_path")
            pkg_date = self.pkg_date
            JPUTitle = "New Item Upload Attempt to: "
            JPUIcon = "STAR"
        
        except Exception as e: 
            print(e)
            category = "Unknown"
            version = "Unknown"
            pkg_name = "Unknown"
            pkg_path = "Unknown"
            pkg_status = "Unknown"
            pkg_date = self.pkg_date
            JPUTitle = "Error Uploading To: "
            JPUIcon = "DESCRIPTION"
    
            
        # VirusTotal data 
        # set VIRUSTOTAL_ALWAYS_REPORT to true to report even if no new package
        try:
            virus_total_analyzer_summary_result = self.env.get("virus_total_analyzer_summary_result")
            vtname = virus_total_analyzer_summary_result["data"]["name"]
            ratio = virus_total_analyzer_summary_result["data"]["ratio"]
            permalink = virus_total_analyzer_summary_result["data"]["permalink"]
        except:
            ratio = "Not Checked"
        if bugged:
            print("****HangoutsChatJPU Information Summary: ")
            print("JSS address: %s" % JSS_URL)
            print("Package: %s" % pkg_name)
            print("Path: %s" % pkg_path)
            print("Version: %s" % version)
            print("Category: %s" % category)
            print("TimeStamp: %s" % pkg_date)
       
        hangoutschat_data = {
            "cards": [
                {
                    "header": {
                        "title": JPUTitle,
                        "subtitle": JSS_URL
                        "icon": JPUIcon
                    },
                    "sections": [
                        {
                            "widgets": [
                                {
                                    "keyValue": {
                                        "topLabel": "Package",
                                        "content": pkg_name,
                                    }
                                },
                                {
                                    "keyValue": {
                                        "topLabel": "Version",
                                        "content": version
                                    }
                                },
                                {
                                    "keyValue": {
                                        "topLabel": "Category",
                                        "content": category
                                    }
                                },
                                {
                                    "keyValue": {
                                        "topLabel": "Virus Total Result",
                                        "content": ratio
                                    }
                                },
                                {
                                    "keyValue": {
                                        "topLabel": "TimeStamp",
                                        "content": pkg_date
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }

        if should_report:
            response = requests.post(webhook_url, json=hangoutschat_data)
            if response.status_code != 200:
                raise ValueError(
                                'Request to Hangouts Chat returned an error %s, the response is:\n%s'
                                % (response.status_code, response.text)
                                )


if __name__ == "__main__":
    processor = HangoutsChatJPUNotifier()
    processor.execute_shell()