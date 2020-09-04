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

from autopkglib import Processor, ProcessorError  # pylint: disable=import-error

# Set the webhook_url to the one provided by Slack when you create the webhook at https://my.slack.com/services/new/incoming-webhook/

__all__ = ["SlackJPUNotifier"]


class Slacker(Processor):
    description = (
        "Posts to Slack via webhook based on output of a JamfPackageUploader run. "
        "Takes elements from "
        "https://gist.github.com/devStepsize/b1b795309a217d24566dcc0ad136f784"
        "and "
        "https://github.com/autopkg/nmcspadden-recipes/blob/master/PostProcessors/Yo.py"
    )
    input_variables = {
        "JSS_URL": {"required": False, "description": ("JSS_URL.")},
        "category": {"required": False, "description": ("Package Category.")},
        "pkg_name": {"required": False, "description": ("Title (NAME)")},
        "jamfpackageuploader_summary_result": {
            "required": False,
            "description": ("Description of interesting results."),
        },
        "slackjpu_webhook_url": {"required": False, "description": ("Slack webhook.")},
    }
    output_variables = {}

    __doc__ = description

    def main(self):
        JSS_URL = self.env.get("JSS_URL")
        webhook_url = self.env.get("slackjpu_webhook_url")
        
        # JPU Summary
        try:
            jamfpackageuploader_summary_result = self.env.get("jamfpackageuploader_summary_result")
            version = jamfpackageuploader_summary_result["data"]["version"]
            category = jamfpackageuploader_summary_result["data"]["category"]
            pkg_name = jamfpackageuploader_summary_result["data"]["pkg_name"]
            pkg_path = jamfpackageuploader_summary_result["data"]["pkg_path"]
            JPUTitle = "New Item Upload Attempt to JSS"
            JPUIcon = ":star:"
        except:
            version = "unknown"
            category = "unknown"
            pkg_name = "unknown"
            pkg_path = "unknown"
            JPUTitle = "Error Running JamfPackageUploader"
            JPUIcon = ":description:"       
        # VirusTotal data if available
        # set VIRUSTOTAL_ALWAYS_REPORT to true to report even if no new package
        try:
            virus_total_analyzer_summary_result = self.env.get("virus_total_analyzer_summary_result")
            vtname = virus_total_analyzer_summary_result["data"]["name"]
            ratio = virus_total_analyzer_summary_result["data"]["ratio"]
            permalink = virus_total_analyzer_summary_result["data"]["permalink"]
        except:
            ratio = "Not Checked"
        
        # output so we can have sanity check
        print("********slackerJPU Information Summary: ")
        print("JSS address: %s" % JSS_URL)
        print("Package: %s" % pkg_name)
        print("Path: %s" % pkg_path)
        print("Version: %s" % version)
        print("Category: %s" % category)     
                
        slack_text = (
            f"*{JPUTitle}*\n"
            "URL: {JSS_URL}\n"
            "Title: *{JPUIcon}* *{pkg_name}*\n"
            "Version: *{version}*\n"
            "Package Category: *{category}*\n"
            "Virus Total Result: *{ratio}*"
            )


        slack_data = {"text": slack_text}

        response = requests.post(webhook_url, json=slack_data)
        if response.status_code != 200:
            raise ValueError(
                f"Request to slack returned an error {response.status_code}, "
                "the response is:\n{response.text}"
            )


if __name__ == "__main__":
    processor = SlackJPUNotifier()
    processor.execute_shell()
