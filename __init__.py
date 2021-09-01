__doc__ = """
Website: 
    https://bitbucket.org/qi/webscraping/

License: 
    LGPL
"""

if __name__ == '__main__':
    import doctest
    for name in ['adt', 'alg', 'common', 'download', 'pdict', 'settings']:
        module = __import__(name)
        print name
        print doctest.testmod(module)
