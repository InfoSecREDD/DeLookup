# DeLookup
## REDD's DeHashed API Lookup Tool

## Overview
DeLookup is a powerful command-line tool designed for cybersecurity professionals, penetration testers, and anyone interested in uncovering compromised credentials across multiple databases by leveraging the Dehashed API. The tool provides an intuitive interface that facilitates the exploration of various personal data points that may have been exposed due to data breaches. 

With DeLookup, users can perform comprehensive searches based on a wide range of parameters, including email addresses, usernames, phone numbers, physical addresses, IP addresses, and even Vehicle Identification Numbers (VINs). The tool aims to assist in identifying potential security risks associated with exposed credentials, empowering users to take proactive measures to protect their sensitive information.

### Key Features:
- **Flexible Search Options**: Users can input multiple search criteria to find relevant information related to a specific person or entity.
- **Reverse Search Capabilities**: In addition to standard searches, DeLookup allows users to conduct reverse lookups on discovered records, helping to surface associated data that may not have been directly searched for.
- **Structured Output**: The results are presented in a clear, organized manner, making it easy for users to interpret the data and identify potential security threats.
- **CSV Export Functionality**: Users can export their search results to a CSV file, enabling further analysis or record-keeping.
- **Environment Configuration**: Sensitive credentials, such as API keys and emails, can be securely managed through a `.env` file, reducing the risk of accidental exposure in code repositories.

## Features

- Search for records using multiple parameters.
- Perform reverse searches on found records.
- Display results in a structured format.
- Optional export of search results to CSV files.
- Environment variable configuration for secure API usage.

## Requirements

- Python 3.6 or higher
- Required Python packages:
  - `requests`
  - `python-dotenv`
  - `rich`
