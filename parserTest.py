from html.parser import HTMLParser
from pyjsparser import parse
import Payloads

class MyHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.result = None

    '''def handle_starttag(self, tag, attrs):
        print("Encountered a start tag:", tag)
        #print("Encountered a start attrs:", attrs)

    def handle_endtag(self, tag):
        print("Encountered an end tag :", tag)
    '''

    def handle_data(self, data):
        if "function" in data:
            ast = parse(data)
            #print(ast)
            self.result = find_key(ast)

def find_key(data):
    inner = []
    replace = None
    pattern = []
    flags = None
    right = None
    regex = None
    upper = None

    def traver(tada):
        nonlocal inner, replace, regex, pattern, flags, right, upper
        if isinstance(tada, dict):
            ks = tada.keys()
            if 'operator' in ks and tada['operator'] == '+':
                if tada['right']['type'] == 'Literal':
                    right = tada['right']['value']
            if 'property' in ks:
                pn = tada['property']['name']
                if pn in ['innerHTML', 'write', 'innerText', 'textContent']:
                    inner.append(pn)
            if 'callee' and 'arguments' in ks:
                if 'name' in tada['callee'].keys() and tada['callee']['name'] == 'eval':
                    inner.append('eval')
                if 'property' in tada['callee'].keys():
                    if tada['callee']['property']['name'] == 'toUpperCase':
                        upper = True
                    if tada['callee']['property']['name'] == 'replace':
                        replace = True
                        if 'regex' in tada['arguments'][0].keys():
                            regex = True
                            pattern.append(tada['arguments'][0]['regex']['pattern'])
                            flags = tada['arguments'][0]['regex']['flags']
                        else:
                            regex = False
                            pattern.append(tada['arguments'][0]['value'])
            for value in tada.values():
                traver(value)
        elif isinstance(tada, list):
            for item in tada:
                traver(item)

    traver(data)
    return inner, replace, regex, pattern, flags, right, upper

def report_check1(check_point_1):
    safe = False
    if check_point_1 != None:
        if 'textContent' in check_point_1 or 'innerText' in check_point_1:
            safe = True
            print(f'You use \'textContent\' or \'innerText\' in your code. \'textContent\' '
                  f'and \'innerText\' properties do not parse HTML, '
                  f'so they are relatively safer when dealing with user input. But '
                  f'they can still be vulnerable to XSS attacks in certain scenarios. Be Careful!')
            print()
        if 'eval' in check_point_1:
            print('You use the method eval() which evaluates a string as JavaScript code. '
                  'If attackers can control the string passed to eval(), for example as an input, '
                  'they can inject malicious HTML or JavaScript code, causing potential xss attack.')
            print('Possible Payloads: alert(1)')
            print('Suggestion: Sanitize your input or set your input with property \'textContent\' or \'innerText\' before executing eval(input)')
            print()
        if 'document.write' in check_point_1:
            print('You use the method document.write() which writes HTML expressions or JavaScript code to a document.'
                  'If attackers can control the string passed to document.write(), for example as an input, '
                  'they can inject malicious HTML or JavaScript code, causing potential xss attack. ')
            print()
        if 'innerHTML' in check_point_1:
            print('You use \'innerHTML\' in you function. This property sets or returns the HTML content of an element. '
                  'If attackers can control the string being inserted as an input, '
                  'they can inject malicious HTML or JavaScript code, causing potential xss attack.'
                  )
            print()
    return safe

def replace_analysis(regex, pattern, flags, upper):
    if regex == True:
        element = []
        for item in pattern:
            if '|' in item:
                element.extend(item.split('|'))
            else:
                if 'auto' in item or 'on' in item or 'script' in item:
                    element.append(item)
                else:
                    element.extend(list(item))
    else:
        element = pattern
    if flags:
        flag_list = list(flags)
    else:
        flag_list = []
    Payloads.report_replace(element, flag_list, upper)
    dict = set(element) - {'[', ']', '(', ')', '`', 'on.*=', 'auto', 'script'}
    if dict and dict != {None}:
        print(f'Your input sanitization contains characters/signs/strings {dict} which cannot be analyzed with this scanner. '
              f'You should use another code scanner to refine your code.')
        print()
    temp_pay = Payloads.find_pl(element, flags, upper)
    return temp_pay


'''main function starts from here'''

'''Replace the file path with the one for your target code file'''
file_path = 'filename.txt'

with open(file_path) as file:
    text = file.read()

parser = MyHTMLParser()
parser.feed(text)
check_point_1, replace, regex, pattern, flags, right, upper = parser.result
print(check_point_1, replace, regex, pattern, flags, right, upper)
print('Report for your code: ')
safe = report_check1(check_point_1)
if replace == True:
    print('You use input sanitization Strategy with method \'replace(A, B)\'. This method'
         'replace input A with B, capture the malicious and suspicious data in the input and replace with safe content.')
    print()
    pl = replace_analysis(regex, pattern, flags, upper)
elif upper == True:
    pl = replace_analysis(regex, pattern, flags, upper)
else:
    pl = Payloads.load_set
if safe == True:
    pl = []
if right != None:
    print(f'Your code use Close-Labels-Early-On Strategy, which put the input inside certain HTML tags: {right}.')
    print()
    addon = Payloads.check_right(right, pattern)
    if addon == None:
        print(f'Unfortunately this scanner is unable to dual with this advanced strategy with {right}. '
              f'You should use other code scaner to refine your code. Thank you')
    else:
        print(f'Please append {addon} before every desire payloads!')
        print()
if not pl:
    print('Your code is relative safe. But there may be potential vulnerabilities in you code '
          'which this scanner is unable to detect. You should use other code scaner to refine your code. '
          'Thank you for your understanding')
else:
    print("Following are some potential payloads may be used to attacked your code:")
    print(pl)
