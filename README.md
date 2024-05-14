# Simple_XSS_Scanner
## Intruduction
In the process of web development, it is important to ensure the security of web application products. Many rookie webpage developers, just like me, may introduce XSS vulnerabilities into their code, which makes their applications susceptible to malicious exploitation. The potential vulnerabilities may be caused by the ignorance or bad functionality of the protective mechanism. In order to help prevent potential XSS vulnerabilities, this project develops a simple XSS vulnerability scanner.
This scanner is intended to give developers a basic understanding of the preventive strategy for XSS attack.

## How to use it
- Clone the project from the GitHub repository Open Terminal in your Mac and navigate to the directory where you want to clone the repository. Use the following command, replacing url with the URL of the repository:
git clone url
- Put your target code file under this project folder
- Open parserTest.py
- Change the path of your target code In parserTest.py, find the line where the path to the target
code file is specified. It might look something like this:
file_path = 'filename.txt'
- Run the file directly from your IDE or terminal by type the following command and press Enter: python parserTest.py
- There will a output report displayed in the terminal.
