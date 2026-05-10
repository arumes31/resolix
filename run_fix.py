import builtins
import fix

_open = builtins.open

def utf8_open(*args, **kwargs):
    if 'b' not in args[1:2] and 'encoding' not in kwargs:
        kwargs['encoding'] = 'utf-8'
    return _open(*args, **kwargs)

builtins.open = utf8_open

if __name__ == "__main__":
    fix.main()
