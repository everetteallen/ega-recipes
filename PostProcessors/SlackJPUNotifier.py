#!/usr/bin/python
#
# Copyright 2017 Graham Pugh
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

from __future__ import absolute_import, print_function

import requests
from datetime import datetime

from autopkglib import Processor, ProcessorError  # pylint: disable=import-error

# Set the webhook_url to the one provided by Slack when you create the webhook at https://my.slack.com/services/new/incoming-webhook/

__all__ = ["SlackJPUNotifier"]


class SlackJPUNotifier(Processor):
    description = (
        "Posts to Slack via webhook based on output of an autopkg run to Jamf Pro. "
        "Takes elements from "
        "https://gist.github.com/devStepsize/b1b795309a217d24566dcc0ad136f784"
        "and "
        "https://github.com/autopkg/nmcspadden-recipes/blob/master/PostProcessors/Yo.py"
    )
    input_variables = {
        "JSS_URL": {"required": False, "description": ("JSS_URL.")},
        "category": {"required": False, "description": ("Package Category.")},
        "pkg_name": {"required": False, "description": ("Title (NAME)")},
        "slackjpu_webhook_url": {"required": False, "description": ("Slack webhook.")},
        "slackjpu_always_report" : {"required": False, "description": ("Should report or not")},
    }
    output_variables = {}

    __doc__ = description

    def main(self):
        JSS_URL = self.env.get("JSS_URL")
        webhook_url = self.env.get("slackjpu_webhook_url")
        bugged = False
        
        #get the local time 
        now = datetime.now()
        self.pkg_date = date_time = now.strftime("%m/%d/%Y, %H:%M:%S")
        
        try:
            should_report = self.env.get("slackjpu_should_report")
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

        except:
            # pkg_status = "unknown"
            version = "unknown"
            category = "unknown"
            pkg_name = "unknown"
            pkg_path = "unknown"
            pkg_date = self.pkg_date
            #pkg_status = "Error Processing Upload to JSS"
            JPUTitle = "Error Running JamfPackageUploader"
            #JPUIcon = ":alarm_clock:"

                 
        # VirusTotal data if available
        # set VIRUSTOTAL_ALWAYS_REPORT to true to report even if no new package
        try:
            virus_total_analyzer_summary_result = self.env.get("virus_total_analyzer_summary_result")
            vtname = virus_total_analyzer_summary_result["data"]["name"]
            ratio = virus_total_analyzer_summary_result["data"]["ratio"]
            permalink = virus_total_analyzer_summary_result["data"]["permalink"]
        except:
            ratio = "Not Checked"
        
        if bugged:
            # output so we can have sanity check
            print("********SlackJPU Information Summary: ")
            print("JSS address: %s" % JSS_URL)
            print("Title: %s" % pkg_name)
            print("Path: %s" % pkg_path)
            print("Version: %s" % version)
            print("Category: %s" % category) 
            print("TimeStamp: %s" % pkg_date)
            print("Ratio: %s" % ratio)    
                
        slack_text = (
            f"*{JPUTitle}* *{JSS_URL}*\nTitle: *{pkg_name}*  Version: *{version}* Category: *{category}*\nVirus Total Result: *{ratio}*     TimeStamp:*{pkg_date}*\n"
        )

        slack_data = {"text": slack_text}
        
        # Only report if slackjpu_should_report is set to true and there is something to report
        if should_report and pkg_name and pkg_name != "unknown":

            response = requests.post(webhook_url, json=slack_data)
            if response.status_code != 200:
                raise ValueError(
                    f"Request to slack returned an error {response.status_code}, "
                    "the response is:\n{response.text}"
                )


if __name__ == "__main__":
    processor = SlackJPUNotifier()
    processor.execute_shell()
