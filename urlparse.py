import re


def unquote_to_bytes(string):
    _hexdig = '0123456789ABCDEFabcdef'
    if not string:
        return b''
    if isinstance(string, str):
        string = string.encode('utf-8')
    bits = string.split(b'%')
    if len(bits) == 1:
        return string
    res = [bits[0]]
    _hextobyte = {(a + b).encode(): bytes([int(a + b, 16)])
                  for a in _hexdig for b in _hexdig}
    for item in bits[1:]:
        try:
            res.append(_hextobyte[item[:2]])
            res.append(item[2:])
        except KeyError:
            res.append(b'%')
            res.append(item)
    return b''.join(res)


def unquote(string, encoding='utf-8', errors='replace'):
    """
    unquote('abc%20def') -> 'abc def'.
    """
    if '%' not in string:
        return string
    _asciire = re.compile('([\x00-\x7f]+)')
    bits = _asciire.split(string)
    res = [bits[0]]
    for i in range(1, len(bits), 2):
        res.append(unquote_to_bytes(bits[i]).decode(encoding, errors))
        res.append(bits[i + 1])
    return ''.join(res)