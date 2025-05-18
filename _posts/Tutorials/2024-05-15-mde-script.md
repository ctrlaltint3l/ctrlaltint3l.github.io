---
title: "MDE Live response file extraction script"
categories:
  - Project
tags:
  - Project
  - MDE

link: github.com/brayden031/MDE_Extraction_Script
---

- Powershell script to safely extract potentially malicious files from an endpoint by combining 7-Zip and MDE's live response getfile feature.
- This script combats the issues faced by using the 'getfile' feature which directly downloads potentially malicious files by using a safer approach of creating a zipped & password protected version before using 'getfile' to retrieve.
